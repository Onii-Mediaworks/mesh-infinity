import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../messaging_state.dart';
import '../widgets/message_bubble.dart';
import '../widgets/composer_bar.dart';

class ThreadScreen extends StatefulWidget {
  const ThreadScreen({super.key, required this.roomId});

  final String roomId;

  @override
  State<ThreadScreen> createState() => _ThreadScreenState();
}

class _ThreadScreenState extends State<ThreadScreen> {
  final _scrollController = ScrollController();
  late MessagingState _messaging;

  @override
  void initState() {
    super.initState();
    _messaging = context.read<MessagingState>();
    _messaging.selectRoom(widget.roomId);
    _messaging.addListener(_scrollToBottom);
  }

  @override
  void dispose() {
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

  String get _roomName {
    final rooms = _messaging.rooms;
    try {
      return rooms.firstWhere((r) => r.id == widget.roomId).name;
    } catch (_) {
      return 'Chat';
    }
  }

  @override
  Widget build(BuildContext context) {
    final messaging = context.watch<MessagingState>();

    return Scaffold(
      appBar: AppBar(
        title: Text(_roomName),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh',
            onPressed: () => messaging.loadMessages(widget.roomId),
          ),
        ],
      ),
      body: Column(
        children: [
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
                          );
                        },
                      ),
          ),
          ComposerBar(
            onSend: (text) => messaging.sendMessage(text),
          ),
        ],
      ),
    );
  }
}
