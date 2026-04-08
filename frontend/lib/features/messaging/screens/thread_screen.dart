// thread_screen.dart
//
// ThreadScreen is the full message thread view for a single room.
// It is the central screen of the messaging feature, and one of the most
// complex in the app because it handles many real-time interactions.
//
// FEATURES HANDLED HERE
// ---------------------
// • Message list — a scrollable ListView of MessageBubble widgets.
// • Auto-scroll — new messages cause the list to animate to the bottom.
// • Typing indicator — shows "Alice is typing…" when remote peers are typing.
// • Reply-to — tapping "Reply" on a message sets _replyTo; the ComposerBar
//   shows the quoted message; sending clears it.
// • Reactions — long-press on a bubble shows an emoji picker; the selected
//   emoji is sent via sendReaction().
// • Edit — outgoing messages can be edited in-place via an AlertDialog.
// • Delete — outgoing messages can be deleted for all participants.
// • Forward — messages can be forwarded to another room via a bottom sheet.
// • LoSec mode (§6.9.6) — the user can request a low-security (1–2 hop) mode
//   for conversations with trusted peers.
//
// SCROLL-TO-MESSAGE
// -----------------
// The [scrollToMessageId] parameter is forwarded from ConversationSearchScreen
// (§22.5.5) to eventually scroll the list to a specific message.  The
// parameter is wired but the scroll implementation is TODO — the infrastructure
// is in place so the call site is correct when the feature is built.
//
// LoSec MODE (§6.9.6)
// --------------------
// LoSec (Low-Security mode) constrains routing to at most 2 hops so that
// metadata cannot traverse the full mesh.  The user opts in voluntarily.
// The backend negotiates LoSec with the remote peer asynchronously:
//   1. The user taps the shield icon → confirmation dialog.
//   2. If confirmed, loSecRequest() is called; the backend sends a LoSec
//      negotiation packet to the peer.
//   3. A LoSecResponseEvent arrives via the EventBus.
//   4. _onBackendEvent handles it: updates _losecMode and shows a SnackBar.
//
// WHY DOES THREAD SCREEN HAVE ITS OWN EventBus SUBSCRIPTION?
// -----------------------------------------------------------
// MessagingState already subscribes to the EventBus for messaging events
// (new messages, room updates, etc.).  ThreadScreen subscribes separately
// only for the LoSecResponseEvent, which is not a messaging event and
// therefore not handled by MessagingState.  Subscribing here keeps the
// LoSec concern isolated to the screen that needs it.

import 'dart:async';
// dart:async provides StreamSubscription for the local EventBus listener.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';
// BackendBridge — used for sendTypingIndicator() and loSecRequest().
import '../../../backend/event_bus.dart';
// EventBus — the background-isolate broadcast stream.
import '../../../backend/event_models.dart';
// BackendEvent and LoSecResponseEvent — typed events.
import '../../../backend/models/message_models.dart';
// MessageModel, ReactionModel — message data models.
import '../../../backend/models/room_models.dart';
// RoomSummary — used to resolve the room name and group/direct flag.
import '../../network/widgets/losec_widgets.dart';
// LoSecBanner — the amber "LoSec active" banner shown at the top of the thread.
// showLoSecRequestDialog — the §6.9.6 consent dialog.
import '../../peers/peers_state.dart';
// PeersState — used to resolve typing peer IDs to display names.
import '../messaging_state.dart';
// MessagingState — message data, send, edit, delete, forward, react.
import '../widgets/message_bubble.dart';
// MessageBubble — renders one message with all its action affordances.
import '../widgets/composer_bar.dart';
// ComposerBar — the text-input row at the bottom with send, reply, typing.
import 'group_detail_screen.dart';
// GroupDetailScreen — pushed when the user taps the group-info icon.

/// Full message thread view for a single room.
///
/// [roomId] identifies which room to display.
/// [scrollToMessageId] optionally deep-links to a specific message (§22.5.5).
class ThreadScreen extends StatefulWidget {
  const ThreadScreen({
    super.key,
    required this.roomId,
    // Optional: if provided, the thread will scroll to this message on open.
    // Set by ConversationSearchScreen (§22.5.5) when the user taps a result.
    // Scroll implementation is TODO — the parameter is wired here so the
    // call site is correct when the scroll feature is built out.
    this.scrollToMessageId,
  });

  final String roomId;

  /// If non-null, the thread attempts to scroll to this message ID on open.
  /// Used by ConversationSearchScreen to deep-link to a specific result (§22.5.5).
  final String? scrollToMessageId;

  @override
  State<ThreadScreen> createState() => _ThreadScreenState();
}

class _ThreadScreenState extends State<ThreadScreen> {
  // ---------------------------------------------------------------------------
  // State fields
  // ---------------------------------------------------------------------------

  /// Controls scrolling in the message ListView.
  /// Used to animate to the bottom when a new message arrives.
  final _scrollController = ScrollController();

  /// Cached reference to MessagingState.
  /// Using late + initState avoids repeated context.read calls and allows
  /// us to add/remove the _scrollToBottom listener directly.
  late MessagingState _messaging;

  /// The message the user is replying to.
  /// Non-null when the user has tapped "Reply" on a bubble.
  /// Shown in ComposerBar as a quoted preview; cleared after sending.
  MessageModel? _replyTo;

  /// Local EventBus subscription for LoSec-specific events.
  /// Separate from MessagingState's subscription because LoSec events are
  /// not messaging events and MessagingState ignores them.
  StreamSubscription<BackendEvent>? _eventSub;

  // LoSec state (§6.9.6) -------------------------------------------------

  /// Current LoSec mode for this conversation.
  /// null = standard (full-mesh routing).
  /// 'losec' = constrained to 1–2 hops.
  String? _losecMode;

  /// Session ID of an in-flight LoSec negotiation (waiting for the remote
  /// peer's response via LoSecResponseEvent).
  /// Null when no negotiation is pending.
  String? _pendingLoSecSession;

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  @override
  void initState() {
    super.initState();

    _messaging = context.read<MessagingState>();

    // Tell MessagingState which room is active — loads messages and marks
    // incoming messages as read.
    _messaging.selectRoom(widget.roomId);

    // Register an auto-scroll listener so that every call to notifyListeners()
    // (which happens when a new message arrives) triggers _scrollToBottom.
    _messaging.addListener(_scrollToBottom);

    // Subscribe to the EventBus for LoSec response events.
    _eventSub = EventBus.instance.stream.listen(_onBackendEvent);
  }

  /// Handles LoSec-specific backend events.
  ///
  /// Only processes [LoSecResponseEvent] and only when we are actually
  /// waiting for a response (_pendingLoSecSession is non-null).  All other
  /// events are passed to the default: branch and ignored.
  void _onBackendEvent(BackendEvent event) {
    switch (event) {
      case LoSecResponseEvent(:final sessionId, :final accepted, :final rejectionReason):
        // Guard: only process the response for the session we initiated.
        // Multiple LoSec sessions can be in flight if the user (or a bug)
        // sends more than one request; we match by sessionId to avoid
        // applying a stale response to the current UI state.
        if (_pendingLoSecSession != null && sessionId == _pendingLoSecSession) {
          _pendingLoSecSession = null; // Clear the pending session regardless of outcome.

          if (accepted) {
            setState(() => _losecMode = 'losec');
            if (mounted) {
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('LoSec mode active — 1-2 hop routing')),
              );
            }
          } else {
            final reason = rejectionReason ?? 'request declined';
            if (mounted) {
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(content: Text('LoSec declined: $reason')),
              );
            }
          }
        }
      default:
        break;
    }
  }

  @override
  void dispose() {
    // Cancel the EventBus subscription to stop receiving events.
    _eventSub?.cancel();

    // Remove the auto-scroll listener from MessagingState.
    // Without this, the closure would keep a reference to _scrollController
    // alive after disposal, causing "use after dispose" errors on scroll.
    _messaging.removeListener(_scrollToBottom);

    _scrollController.dispose();
    super.dispose();
  }

  // ---------------------------------------------------------------------------
  // Auto-scroll
  // ---------------------------------------------------------------------------

  /// Animates the ListView to the bottom after the next frame is rendered.
  ///
  /// WHY use addPostFrameCallback instead of scrolling immediately?
  /// When a new message arrives, notifyListeners() triggers a rebuild.
  /// The scroll position's maxScrollExtent updates only AFTER the new item
  /// is laid out — i.e. after the frame completes.  addPostFrameCallback
  /// delays the scroll until after that layout pass so we scroll to the
  /// actual bottom, not the stale previous bottom.
  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      // hasClients is false if the ListView is not yet attached (e.g. still
      // loading) — scrolling on a controller with no client throws.
      if (_scrollController.hasClients) {
        _scrollController.animateTo(
          _scrollController.position.maxScrollExtent,
          duration: const Duration(milliseconds: 300),
          curve: Curves.easeOut,
        );
      }
    });
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /// Looks up the RoomSummary for this thread's room.
  ///
  /// Returns null if the room list has not loaded yet or if the room was deleted.
  /// Nullable so the AppBar title can fall back to 'Chat' gracefully.
  RoomSummary? get _room {
    final rooms = _messaging.rooms;
    final match = rooms.where((r) => r.id == widget.roomId);
    return match.isNotEmpty ? match.first : null;
  }

  /// The display name for the AppBar title.
  /// Falls back to 'Chat' if the room hasn't loaded yet.
  String get _roomName => _room?.name ?? 'Chat';

  // ---------------------------------------------------------------------------
  // Message action handlers
  // ---------------------------------------------------------------------------

  /// Sets the reply-to context and triggers a ComposerBar rebuild.
  void _setReplyTo(MessageModel msg) {
    setState(() => _replyTo = msg);
  }

  /// Clears the reply-to context (called when the user cancels or sends).
  void _clearReply() {
    setState(() => _replyTo = null);
  }

  /// Routes a send action through either replyToMessage or sendMessage
  /// depending on whether a reply-to is set.
  ///
  /// After sending a reply, the reply context is cleared so the next
  /// message is sent as a standalone message, not another reply.
  void _handleSend(String text) {
    if (_replyTo != null) {
      // Send as a reply to the quoted message.
      _messaging.replyToMessage(widget.roomId, _replyTo!.id, text);
      _clearReply();
    } else {
      // Send as a new standalone message in the active room.
      _messaging.sendMessage(text);
    }
  }

  /// Forwards typing state changes to the backend so the remote peer sees
  /// the "…is typing" indicator (§10.2.1).
  void _handleTypingChanged(bool isTyping) {
    context.read<BackendBridge>().sendTypingIndicator(widget.roomId, isTyping);
  }

  /// Sends an emoji reaction to [msg].
  void _handleReact(MessageModel msg, String emoji) {
    _messaging.sendReaction(widget.roomId, msg.id, emoji);
  }

  /// Opens an edit dialog pre-populated with [msg]'s current text.
  ///
  /// The TextEditingController is created inside the dialog and disposed
  /// via .then() after the dialog closes to avoid a resource leak.
  void _handleEdit(MessageModel msg) {
    final controller = TextEditingController(text: msg.text);
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Edit message'),
        content: TextField(
          controller: controller,
          maxLines: 4,
          minLines: 1,
          autofocus: true,
          decoration: const InputDecoration(
            hintText: 'Edit your message',
            border: OutlineInputBorder(),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () {
              final newText = controller.text.trim();
              // Only call editMessage if the text actually changed — avoids
              // a no-op backend call that would generate a spurious "edited"
              // indicator on an unchanged message.
              if (newText.isNotEmpty && newText != msg.text) {
                _messaging.editMessage(widget.roomId, msg.id, newText);
              }
              Navigator.pop(ctx);
            },
            child: const Text('Save'),
          ),
        ],
      ),
      // Dispose the controller after the dialog Future completes so that
      // platform text-input resources are released regardless of whether
      // the user saved or cancelled.
    ).then((_) => controller.dispose());
  }

  /// Deletes [msg] for all participants in the room.
  void _handleDeleteForEveryone(MessageModel msg) {
    _messaging.deleteForEveryone(widget.roomId, msg.id);
  }

  // ---------------------------------------------------------------------------
  // LoSec request handler (§6.9.6)
  // ---------------------------------------------------------------------------

  /// Handles the LoSec shield button tap.
  ///
  /// TWO CODE PATHS:
  ///   If _losecMode == 'losec':  immediately revert to standard routing.
  ///   Otherwise:  show the §6.9.6 consent dialog, send the LoSec request,
  ///               and wait for a LoSecResponseEvent.
  ///
  /// Session ID generation:
  ///   A 32-byte pseudo-random session ID is constructed from the current
  ///   microsecond timestamp's low byte.  This is sufficient for a nonce
  ///   that correlates the request with its response; it is not a
  ///   cryptographic secret.
  Future<void> _handleLoSecRequest() async {
    // If already in LoSec mode, toggling the button reverts to standard routing.
    if (_losecMode == 'losec') {
      setState(() => _losecMode = null);
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Reverted to standard (full mesh) routing')),
      );
      return;
    }

    // Show the explicit consent dialog required by §6.9.6.
    // confirmed is false if the user cancelled.
    final confirmed = await showLoSecRequestDialog(context);
    if (!confirmed || !mounted) return;

    final bridge = context.read<BackendBridge>();

    // Generate a 32-byte pseudo-random session ID from microsecond clock bits.
    // This produces a 64-character hex string used to correlate the request
    // with the incoming LoSecResponseEvent.
    final sessionIdBytes = List<int>.generate(
      32,
      (_) => DateTime.now().microsecondsSinceEpoch & 0xFF,
    );
    final sessionId =
        sessionIdBytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

    final result = bridge.loSecRequest(
      sessionId: sessionId,
      mode: 'losec',
      hopCount: 2,
      reason: 'user requested',
      // _room?.otherPeerId is null for group rooms — the backend handles
      // group LoSec differently from direct-room LoSec.
      peerId: _room?.otherPeerId,
    );

    if (result == null) {
      // Backend returned null — LoSec subsystem unavailable or misconfigured.
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('LoSec request failed — backend unavailable')),
        );
      }
      return;
    }

    if (result['sent'] == true) {
      // Asynchronous path: the request was forwarded to the remote peer.
      // Store the session ID so _onBackendEvent can match the response.
      _pendingLoSecSession = sessionId;
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('LoSec request sent — waiting for peer response…')),
        );
      }
      return;
    }

    // Synchronous path (e.g. local simulation / testing backend):
    // the result contains an immediate accept/reject.
    final accepted = result['accepted'] as bool? ?? false;
    if (accepted) {
      setState(() => _losecMode = 'losec');
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('LoSec mode active — 1-2 hop routing')),
        );
      }
    } else {
      final reason = result['rejection_reason'] as String? ?? 'request declined';
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('LoSec declined: $reason')),
        );
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Forward handler
  // ---------------------------------------------------------------------------

  /// Opens a bottom sheet listing other rooms to forward [msg] to.
  ///
  /// The current room is excluded from the list — forwarding to the same
  /// room you're already in is a no-op and confusing.
  void _handleForward(MessageModel msg) {
    // All rooms except the current one are valid forwarding destinations.
    final rooms = _messaging.rooms
        .where((r) => r.id != widget.roomId)
        .toList();

    if (rooms.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('No other rooms to forward to')),
      );
      return;
    }

    showModalBottomSheet<void>(
      context: context,
      builder: (ctx) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Padding(
              padding: const EdgeInsets.all(16),
              child: Text(
                'Forward to',
                style: Theme.of(context).textTheme.titleSmall,
              ),
            ),
            // Limit the sheet height to 40% of the screen so it doesn't
            // cover the full screen on phones with many rooms.
            ConstrainedBox(
              constraints: BoxConstraints(
                maxHeight: MediaQuery.sizeOf(context).height * 0.4,
              ),
              child: ListView.builder(
                shrinkWrap: true,
                itemCount: rooms.length,
                itemBuilder: (_, i) => ListTile(
                  leading: const Icon(Icons.chat_outlined),
                  title: Text(rooms[i].name),
                  onTap: () {
                    // Close the bottom sheet before showing the SnackBar
                    // to avoid a "showSnackBar while sheet is open" assertion.
                    Navigator.pop(ctx);
                    _messaging.forwardMessage(
                      widget.roomId, msg.id, rooms[i].id,
                    );
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(
                        content: Text('Forwarded to ${rooms[i].name}'),
                      ),
                    );
                  },
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    // context.watch subscribes to both state objects so the thread rebuilds
    // when new messages arrive (MessagingState) and when typing peer names
    // need to be resolved (PeersState).
    final messaging = context.watch<MessagingState>();
    final peers = context.watch<PeersState>();

    // Resolve typing peer IDs to human-readable display names.
    // Falls back to a truncated peer ID (8 chars) for peers not in PeersState.
    final typingNames = messaging.typingPeers.map((id) {
      final match = peers.peers.where((p) => p.id == id);
      return match.isNotEmpty ? match.first.name : id.substring(0, 8);
    }).toList();

    return Scaffold(
      appBar: AppBar(
        title: Text(_roomName),
        actions: [
          // Group info icon — only shown for group rooms.
          // groupId can be null if the room is not linked to a group
          // (should not happen for isGroup rooms, but guard defensively).
          if (_room?.isGroup == true)
            IconButton(
              icon: const Icon(Icons.group_outlined),
              tooltip: 'Group info',
              onPressed: () {
                final groupId = _room!.groupId;
                if (groupId != null) {
                  Navigator.push(
                    context,
                    MaterialPageRoute(
                      builder: (_) => GroupDetailScreen(groupId: groupId),
                    ),
                  );
                }
              },
            ),

          // LoSec shield icon — amber when active, outline when inactive (§6.9.6).
          // Tooltip changes to reflect current mode so the user understands
          // what tapping will do.
          IconButton(
            icon: Icon(
              _losecMode == 'losec' ? Icons.shield : Icons.shield_outlined,
              color: _losecMode == 'losec' ? Colors.amber.shade700 : null,
            ),
            tooltip: _losecMode == 'losec'
                ? 'LoSec active — tap to revert'
                : 'Request low-security mode',
            onPressed: _handleLoSecRequest,
          ),

          // Refresh button — manually reloads messages from the backend.
          // Useful if a background event was missed (rare but possible).
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh',
            onPressed: () => messaging.loadMessages(widget.roomId),
          ),
        ],
      ),
      body: Column(
        children: [
          // LoSec active banner — visible amber bar when LoSec mode is on.
          if (_losecMode == 'losec') const LoSecBanner(),

          // Main message area — expands to fill available height.
          Expanded(
            child: messaging.loadingMessages
                // Loading spinner while fetchMessages() is in flight.
                ? const Center(child: CircularProgressIndicator())
                : messaging.messages.isEmpty
                    // Empty state — no messages yet.
                    ? Center(
                        child: Text(
                          'No messages yet. Say hello!',
                          style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                            color: Theme.of(context).colorScheme.outline,
                          ),
                        ),
                      )
                    // Message list — one MessageBubble per message.
                    : ListView.builder(
                        controller: _scrollController,
                        padding: const EdgeInsets.symmetric(vertical: 8),
                        itemCount: messaging.messages.length,
                        itemBuilder: (ctx, i) {
                          final msg = messaging.messages[i];
                          return MessageBubble(
                            message: msg,
                            onDelete: () => messaging.deleteMessage(msg.id),
                            onReply: () => _setReplyTo(msg),
                            onReact: (emoji) => _handleReact(msg, emoji),
                            // Edit and delete-for-everyone are only available
                            // on messages the local user sent (isOutgoing).
                            onEdit: msg.isOutgoing
                                ? () => _handleEdit(msg)
                                : null,
                            onDeleteForEveryone: msg.isOutgoing
                                ? () => _handleDeleteForEveryone(msg)
                                : null,
                            onForward: () => _handleForward(msg),
                          );
                        },
                      ),
          ),

          // Typing indicator bar (§10.2.1) — shown above the composer when
          // one or more remote peers are actively typing.
          if (typingNames.isNotEmpty)
            _TypingIndicatorBar(names: typingNames),

          // Composer bar — text input + send button + reply preview.
          ComposerBar(
            onSend: _handleSend,
            replyTo: _replyTo,
            onCancelReply: _clearReply,
            onTypingChanged: _handleTypingChanged,
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _TypingIndicatorBar — "Alice is typing…" bar above the composer (§10.2.1)
// ---------------------------------------------------------------------------

/// A narrow bar displayed above [ComposerBar] when one or more remote peers
/// are actively typing in the current room.
///
/// Adapts the label for 1, 2, or 3+ concurrent typists:
///   1 peer → "Alice is typing…"
///   2 peers → "Alice and Bob are typing…"
///   3+ peers → "3 people are typing…"
class _TypingIndicatorBar extends StatelessWidget {
  const _TypingIndicatorBar({required this.names});

  /// The display names (or truncated peer IDs) of peers currently typing.
  final List<String> names;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    // Build the human-readable label based on the number of typing peers.
    final label = switch (names.length) {
      1 => '${names[0]} is typing…',
      2 => '${names[0]} and ${names[1]} are typing…',
      // For 3+ typists a count is less overwhelming than listing all names.
      _ => '${names.length} people are typing…',
    };

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      decoration: BoxDecoration(
        // surfaceContainerLow is slightly elevated over the scaffold background
        // so the bar is visually distinct without being obtrusive.
        color: cs.surfaceContainerLow,
        // Top border separates the indicator from the message list.
        border: Border(top: BorderSide(color: cs.outlineVariant, width: 0.5)),
      ),
      child: Text(
        label,
        style: Theme.of(context).textTheme.labelSmall?.copyWith(
          color: cs.onSurfaceVariant,
          // Italic styling visually distinguishes typing state from messages.
          fontStyle: FontStyle.italic,
        ),
      ),
    );
  }
}
