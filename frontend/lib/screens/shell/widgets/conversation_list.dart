import 'package:flutter/material.dart';

import '../../../models/thread_models.dart';

class ConversationList extends StatelessWidget {
  const ConversationList({
    super.key,
    required this.messages,
    required this.padding,
  });

  final List<MessageItem> messages;
  final double padding;

  @override
  Widget build(BuildContext context) {
    return ListView.separated(
      padding: EdgeInsets.all(padding),
      itemCount: messages.length,
      separatorBuilder: (_, __) => const SizedBox(height: 12),
      itemBuilder: (context, index) {
        final message = messages[index];
        return _MessageBubble(message: message);
      },
    );
  }
}

class _MessageBubble extends StatelessWidget {
  const _MessageBubble({required this.message});

  final MessageItem message;

  @override
  Widget build(BuildContext context) {
    return Align(
      alignment: message.isOutgoing ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        margin: const EdgeInsets.only(bottom: 2),
        padding: const EdgeInsets.all(14),
        constraints: const BoxConstraints(maxWidth: 420),
        decoration: BoxDecoration(
          color: message.isOutgoing ? const Color(0xFF2C6EE2) : Colors.white,
          borderRadius: BorderRadius.circular(16),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withOpacity(0.04),
              blurRadius: 12,
              offset: const Offset(0, 6),
            ),
          ],
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (!message.isOutgoing)
              Text(message.sender,
                  style: const TextStyle(fontSize: 11, color: Color(0xFF7B8188))),
            Text(
              message.text,
              style: TextStyle(
                color: message.isOutgoing ? Colors.white : const Color(0xFF1C2127),
              ),
            ),
            const SizedBox(height: 6),
            Text(
              message.timestamp,
              style: TextStyle(
                fontSize: 10,
                color: message.isOutgoing ? Colors.white70 : const Color(0xFF9AA0A6),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
