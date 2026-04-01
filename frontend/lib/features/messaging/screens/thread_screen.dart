import 'dart:async';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';
import '../../../backend/event_bus.dart';
import '../../../backend/event_models.dart';
import '../../../backend/models/message_models.dart';
import '../../../backend/models/room_models.dart';
import '../../network/widgets/losec_widgets.dart';
import '../../peers/peers_state.dart';
import '../messaging_state.dart';
import '../widgets/message_bubble.dart';
import '../widgets/composer_bar.dart';
import 'group_detail_screen.dart';

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
  final _scrollController = ScrollController();
  late MessagingState _messaging;
  MessageModel? _replyTo;
  StreamSubscription<BackendEvent>? _eventSub;

  // LoSec connection mode for this conversation thread.
  // null = standard (full mesh), 'losec' = 1-2 hop, 'direct' = 0 hop.
  String? _losecMode;
  // Session ID of the pending LoSec request (waiting for async response).
  String? _pendingLoSecSession;

  @override
  void initState() {
    super.initState();
    _messaging = context.read<MessagingState>();
    _messaging.selectRoom(widget.roomId);
    _messaging.addListener(_scrollToBottom);
    _eventSub = EventBus.instance.stream.listen(_onBackendEvent);
  }

  void _onBackendEvent(BackendEvent event) {
    switch (event) {
      case LoSecResponseEvent(:final sessionId, :final accepted, :final rejectionReason):
        if (_pendingLoSecSession != null && sessionId == _pendingLoSecSession) {
          _pendingLoSecSession = null;
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
    _eventSub?.cancel();
    _messaging.removeListener(_scrollToBottom);
    _scrollController.dispose();
    super.dispose();
  }

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scrollController.hasClients) {
        _scrollController.animateTo(
          _scrollController.position.maxScrollExtent,
          duration: const Duration(milliseconds: 300),
          curve: Curves.easeOut,
        );
      }
    });
  }

  RoomSummary? get _room {
    final rooms = _messaging.rooms;
    final match = rooms.where((r) => r.id == widget.roomId);
    return match.isNotEmpty ? match.first : null;
  }

  String get _roomName => _room?.name ?? 'Chat';

  void _setReplyTo(MessageModel msg) {
    setState(() => _replyTo = msg);
  }

  void _clearReply() {
    setState(() => _replyTo = null);
  }

  void _handleSend(String text) {
    if (_replyTo != null) {
      _messaging.replyToMessage(widget.roomId, _replyTo!.id, text);
      _clearReply();
    } else {
      _messaging.sendMessage(text);
    }
  }

  void _handleTypingChanged(bool isTyping) {
    context.read<BackendBridge>().sendTypingIndicator(widget.roomId, isTyping);
  }

  void _handleReact(MessageModel msg, String emoji) {
    _messaging.sendReaction(widget.roomId, msg.id, emoji);
  }

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
              if (newText.isNotEmpty && newText != msg.text) {
                _messaging.editMessage(widget.roomId, msg.id, newText);
              }
              Navigator.pop(ctx);
            },
            child: const Text('Save'),
          ),
        ],
      ),
    ).then((_) => controller.dispose());
  }

  void _handleDeleteForEveryone(MessageModel msg) {
    _messaging.deleteForEveryone(widget.roomId, msg.id);
  }

  Future<void> _handleLoSecRequest() async {
    // If already in LoSec mode, offer to revert to standard.
    if (_losecMode == 'losec') {
      setState(() => _losecMode = null);
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Reverted to standard (full mesh) routing')),
      );
      return;
    }

    // Show the confirmation dialog (§6.9.6 — user must explicitly consent).
    final confirmed = await showLoSecRequestDialog(context);
    if (!confirmed || !mounted) return;

    final bridge = context.read<BackendBridge>();

    // Generate a random 32-byte session ID.
    final sessionIdBytes = List<int>.generate(32, (_) => DateTime.now().microsecondsSinceEpoch & 0xFF);
    final sessionId = sessionIdBytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

    final result = bridge.loSecRequest(
      sessionId: sessionId,
      mode: 'losec',
      hopCount: 2,
      reason: 'user requested',
      peerId: _room?.otherPeerId,
    );

    if (result == null) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('LoSec request failed — backend unavailable')),
        );
      }
      return;
    }

    // If the request was sent over the wire, wait for the async LoSecResponseEvent.
    if (result['sent'] == true) {
      _pendingLoSecSession = sessionId;
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('LoSec request sent — waiting for peer response…')),
        );
      }
      return;
    }

    // Synchronous (local simulation) path.
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

  void _handleForward(MessageModel msg) {
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

  @override
  Widget build(BuildContext context) {
    final messaging = context.watch<MessagingState>();
    final peers = context.watch<PeersState>();

    // Resolve typing peer IDs to display names for the indicator label.
    final typingNames = messaging.typingPeers.map((id) {
      final match = peers.peers.where((p) => p.id == id);
      return match.isNotEmpty ? match.first.name : id.substring(0, 8);
    }).toList();

    return Scaffold(
      appBar: AppBar(
        title: Text(_roomName),
        actions: [
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
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh',
            onPressed: () => messaging.loadMessages(widget.roomId),
          ),
        ],
      ),
      body: Column(
        children: [
          if (_losecMode == 'losec') const LoSecBanner(),
          Expanded(
            child: messaging.loadingMessages
                ? const Center(child: CircularProgressIndicator())
                : messaging.messages.isEmpty
                    ? Center(
                        child: Text(
                          'No messages yet. Say hello!',
                          style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                            color: Theme.of(context).colorScheme.outline,
                          ),
                        ),
                      )
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
          // Typing indicator (§10.2.1) — shown only when peers are actively typing.
          if (typingNames.isNotEmpty)
            _TypingIndicatorBar(names: typingNames),
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

/// Compact bar shown above the composer when one or more remote peers are typing.
class _TypingIndicatorBar extends StatelessWidget {
  const _TypingIndicatorBar({required this.names});
  final List<String> names;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final label = switch (names.length) {
      1 => '${names[0]} is typing…',
      2 => '${names[0]} and ${names[1]} are typing…',
      _ => '${names.length} people are typing…',
    };
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      decoration: BoxDecoration(
        color: cs.surfaceContainerLow,
        border: Border(top: BorderSide(color: cs.outlineVariant, width: 0.5)),
      ),
      child: Text(
        label,
        style: Theme.of(context).textTheme.labelSmall?.copyWith(
          color: cs.onSurfaceVariant,
          fontStyle: FontStyle.italic,
        ),
      ),
    );
  }
}
