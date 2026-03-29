import 'package:flutter/material.dart';

import '../../../backend/models/message_models.dart';

class ComposerBar extends StatefulWidget {
  const ComposerBar({
    super.key,
    required this.onSend,
    this.onAttach,
    this.replyTo,
    this.onCancelReply,
    this.onTypingChanged,
  });

  final ValueChanged<String> onSend;
  final VoidCallback? onAttach;
  final MessageModel? replyTo;
  final VoidCallback? onCancelReply;
  /// Called with `true` when the user starts typing and `false` when they stop
  /// (by clearing the field or sending).  Used to broadcast typing indicators.
  final ValueChanged<bool>? onTypingChanged;

  @override
  State<ComposerBar> createState() => _ComposerBarState();
}

class _ComposerBarState extends State<ComposerBar> {
  final _controller = TextEditingController();
  bool _hasText = false;

  @override
  void initState() {
    super.initState();
    _controller.addListener(() {
      final has = _controller.text.trim().isNotEmpty;
      if (has != _hasText) {
        setState(() => _hasText = has);
        widget.onTypingChanged?.call(has);
      }
    });
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _send() {
    final text = _controller.text.trim();
    if (text.isEmpty) return;
    widget.onSend(text);
    _controller.clear();
    // Clearing the field will fire the listener and set _hasText=false,
    // but call onTypingChanged explicitly here to guarantee the "stopped
    // typing" signal is sent even if the listener fires after the send.
    widget.onTypingChanged?.call(false);
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return SafeArea(
      child: Container(
        decoration: BoxDecoration(
          color: cs.surface,
          border: Border(top: BorderSide(color: cs.outlineVariant)),
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (widget.replyTo != null) _ReplyPreview(
              message: widget.replyTo!,
              onCancel: widget.onCancelReply,
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
              child: Row(
                children: [
                  if (widget.onAttach != null)
                    IconButton(
                      onPressed: widget.onAttach,
                      icon: const Icon(Icons.attach_file_rounded),
                      tooltip: 'Attach file',
                    ),
                  Expanded(
                    child: TextField(
                      controller: _controller,
                      maxLines: 4,
                      minLines: 1,
                      textCapitalization: TextCapitalization.sentences,
                      decoration: InputDecoration(
                        hintText: 'Message',
                        contentPadding:
                            const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                        isDense: true,
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(24),
                          borderSide: BorderSide.none,
                        ),
                      ),
                      onSubmitted: (_) => _send(),
                    ),
                  ),
                  const SizedBox(width: 4),
                  AnimatedContainer(
                    duration: const Duration(milliseconds: 150),
                    child: _hasText
                        ? IconButton.filled(
                            onPressed: _send,
                            icon: const Icon(Icons.send_rounded),
                            tooltip: 'Send',
                          )
                        : IconButton(
                            onPressed: null,
                            icon: Icon(Icons.send_rounded, color: cs.outline),
                          ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _ReplyPreview extends StatelessWidget {
  const _ReplyPreview({required this.message, this.onCancel});

  final MessageModel message;
  final VoidCallback? onCancel;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final ts = Theme.of(context).textTheme;
    return Container(
      padding: const EdgeInsets.only(left: 16, right: 8, top: 8, bottom: 4),
      decoration: BoxDecoration(
        border: Border(bottom: BorderSide(color: cs.outlineVariant, width: 0.5)),
      ),
      child: Row(
        children: [
          Container(
            width: 3,
            height: 32,
            decoration: BoxDecoration(
              color: cs.primary,
              borderRadius: BorderRadius.circular(2),
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  message.sender,
                  style: ts.labelSmall?.copyWith(
                    color: cs.primary,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                Text(
                  message.text,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: ts.bodySmall?.copyWith(color: cs.onSurfaceVariant),
                ),
              ],
            ),
          ),
          IconButton(
            onPressed: onCancel,
            icon: const Icon(Icons.close, size: 18),
            tooltip: 'Cancel reply',
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
          ),
        ],
      ),
    );
  }
}
