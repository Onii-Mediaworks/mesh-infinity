import 'package:flutter/material.dart';

import '../../../models/thread_models.dart';

class ConversationList extends StatefulWidget {
  const ConversationList({
    super.key,
    required this.messages,
    this.emptyState,
  });

  final List<MessageItem> messages;
  final Widget? emptyState;

  @override
  State<ConversationList> createState() => _ConversationListState();
}

class _ConversationListState extends State<ConversationList> {
  final ScrollController _scroll = ScrollController();

  @override
  void initState() {
    super.initState();
    _scrollToEnd();
  }

  @override
  void didUpdateWidget(covariant ConversationList oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.messages.length != oldWidget.messages.length) {
      _scrollToEnd();
    }
  }

  void _scrollToEnd() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scroll.hasClients && _scroll.position.hasContentDimensions) {
        _scroll.animateTo(
          _scroll.position.maxScrollExtent,
          duration: const Duration(milliseconds: 300),
          curve: Curves.easeOut,
        );
      }
    });
  }

  @override
  void dispose() {
    _scroll.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final msgs = widget.messages;
    if (msgs.isEmpty) {
      return widget.emptyState ?? const SizedBox.shrink();
    }
    return ListView.builder(
      controller: _scroll,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      itemCount: msgs.length,
      itemBuilder: (context, i) {
        final msg = msgs[i];
        final prev = i > 0 ? msgs[i - 1] : null;
        final next = i < msgs.length - 1 ? msgs[i + 1] : null;

        final sameAsPrev = prev != null &&
            prev.isOutgoing == msg.isOutgoing &&
            prev.sender == msg.sender;
        final sameAsNext = next != null &&
            next.isOutgoing == msg.isOutgoing &&
            next.sender == msg.sender;

        return Padding(
          padding: EdgeInsets.only(top: sameAsPrev ? 3 : 12),
          child: _Bubble(
            message: msg,
            showSender: !msg.isOutgoing && !sameAsPrev,
            isFirstInGroup: !sameAsPrev,
            isLastInGroup: !sameAsNext,
          ),
        );
      },
    );
  }
}

class _Bubble extends StatelessWidget {
  const _Bubble({
    super.key,
    required this.message,
    required this.showSender,
    required this.isFirstInGroup,
    required this.isLastInGroup,
  });

  final MessageItem message;
  final bool showSender;
  final bool isFirstInGroup;
  final bool isLastInGroup;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final out = message.isOutgoing;

    final bubbleColor = out ? cs.primary : cs.surfaceContainerHighest;
    final textColor = out ? cs.onPrimary : cs.onSurfaceVariant;
    final tsColor = out
        ? cs.onPrimary.withValues(alpha: 0.6)
        : cs.onSurfaceVariant;

    // Signal-style corner radii: the side facing the centre is tight in a group
    const big = 18.0;
    const tiny = 4.0;
    final radius = out
        ? BorderRadius.only(
            topLeft: const Radius.circular(big),
            topRight: Radius.circular(isFirstInGroup ? big : tiny),
            bottomRight: Radius.circular(isLastInGroup ? big : tiny),
            bottomLeft: const Radius.circular(big),
          )
        : BorderRadius.only(
            topLeft: Radius.circular(isFirstInGroup ? big : tiny),
            topRight: const Radius.circular(big),
            bottomRight: const Radius.circular(big),
            bottomLeft: Radius.circular(isLastInGroup ? big : tiny),
          );

    return Column(
      crossAxisAlignment: out ? CrossAxisAlignment.end : CrossAxisAlignment.start,
      children: [
        if (showSender)
          Padding(
            padding: const EdgeInsets.only(left: 14, bottom: 2),
            child: Text(
              message.sender,
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                color: cs.onSurfaceVariant,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
        Container(
          constraints: const BoxConstraints(maxWidth: 420),
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
          decoration: BoxDecoration(
            color: bubbleColor,
            borderRadius: radius,
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: 0.06),
                blurRadius: 3,
                offset: const Offset(0, 2),
              ),
            ],
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(message.text, style: TextStyle(color: textColor, fontSize: 15, height: 1.4)),
              const SizedBox(height: 4),
              Text(message.timestamp, style: TextStyle(fontSize: 10, color: tsColor)),
            ],
          ),
        ),
      ],
    );
  }
}
