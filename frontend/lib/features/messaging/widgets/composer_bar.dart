import 'package:flutter/material.dart';

import '../../../backend/models/message_models.dart';

/// ComposerBar — the message input strip at the bottom of a thread.
///
/// Responsibilities:
///   - Accepts multi-line text input (up to 4 lines before scrolling).
///   - Optionally shows an attachment button (caller supplies [onAttach]).
///   - Optionally shows a "reply-to" preview strip above the input when
///     [replyTo] is non-null (§10.3.2 threaded replies).
///   - Fires [onTypingChanged] with `true` the moment text appears and `false`
///     when the field clears or the message is sent — callers use this to
///     broadcast typing indicators over the transport (§10.2.1).
///   - Fires [onSend] with the trimmed text when the user taps Send or submits.
///
/// The widget is stateful only because it needs to watch the text controller
/// to know whether to show the active Send button.
class ComposerBar extends StatefulWidget {
  const ComposerBar({
    super.key,
    required this.onSend,
    this.onAttach,
    this.replyTo,
    this.onCancelReply,
    this.onTypingChanged,
  });

  /// Called with the trimmed message text when the user sends.
  final ValueChanged<String> onSend;

  /// Optional: when present, an attachment-clip icon button is shown to the
  /// left of the text field.  Null hides the button entirely.
  final VoidCallback? onAttach;

  /// When non-null, a [_ReplyPreview] strip is shown above the text field so
  /// the user can see which message they are replying to.  Null = no reply.
  final MessageModel? replyTo;

  /// Called when the user taps the × on the reply preview strip.
  final VoidCallback? onCancelReply;

  /// Called with `true` when the user starts typing and `false` when they stop
  /// (by clearing the field or sending).  Used to broadcast typing indicators.
  final ValueChanged<bool>? onTypingChanged;

  @override
  State<ComposerBar> createState() => _ComposerBarState();
}

class _ComposerBarState extends State<ComposerBar> {
  /// Controls the text field and lets us read/clear its content.
  final _controller = TextEditingController();

  /// Tracks whether the field has any non-whitespace text.  Drives whether
  /// the Send button is active (filled) or disabled (outlined).
  bool _hasText = false;

  @override
  void initState() {
    super.initState();
    // Listen for every text change so we can update _hasText reactively.
    // We check `.trim().isNotEmpty` so that a field containing only spaces
    // does not count as "has text" — we would never send a blank message.
    _controller.addListener(() {
      final has = _controller.text.trim().isNotEmpty;
      if (has != _hasText) {
        // Only rebuild when the boolean actually flips; avoids redundant frames.
        setState(() => _hasText = has);
        // Notify the caller so it can broadcast/cancel the typing indicator.
        widget.onTypingChanged?.call(has);
      }
    });
  }

  @override
  void dispose() {
    // Always dispose controllers to free their internal ChangeNotifier resources.
    _controller.dispose();
    super.dispose();
  }

  /// Validate, emit, and clear the current message.
  void _send() {
    final text = _controller.text.trim();
    // Guard: never send an empty message even if the button somehow fires.
    if (text.isEmpty) return;
    widget.onSend(text);
    _controller.clear();
    // Clearing the field fires the listener and sets _hasText = false,
    // but we also call onTypingChanged explicitly here to guarantee the
    // "stopped typing" signal is sent even if the listener fires after the
    // send completes (e.g. due to microtask scheduling order).
    widget.onTypingChanged?.call(false);
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    // SafeArea keeps the bar above the on-screen keyboard / system navigation.
    return SafeArea(
      child: Container(
        decoration: BoxDecoration(
          color: cs.surface,
          // Subtle top border visually separates the composer from the message list.
          border: Border(top: BorderSide(color: cs.outlineVariant)),
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Show reply preview strip only when replying to a message.
            if (widget.replyTo != null) _ReplyPreview(
              message: widget.replyTo!,
              onCancel: widget.onCancelReply,
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
              child: Row(
                children: [
                  // Attachment button: only rendered when the caller cares
                  // about attachments.  Absent in read-only or limited rooms.
                  if (widget.onAttach != null)
                    IconButton(
                      onPressed: widget.onAttach,
                      icon: const Icon(Icons.attach_file_rounded),
                      tooltip: 'Attach file',
                    ),
                  Expanded(
                    child: TextField(
                      controller: _controller,
                      // Allow up to 4 lines before the field starts scrolling.
                      maxLines: 4,
                      minLines: 1,
                      // Auto-capitalise the first letter of each sentence for
                      // convenience on mobile keyboards.
                      textCapitalization: TextCapitalization.sentences,
                      decoration: InputDecoration(
                        hintText: 'Message',
                        contentPadding:
                            const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                        // isDense shrinks internal padding to keep the field compact.
                        isDense: true,
                        // Pill-shaped border with no visible border line — the
                        // filled background is the visual container.
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(24),
                          borderSide: BorderSide.none,
                        ),
                      ),
                      // Hardware-keyboard Enter key triggers a send, matching
                      // the desktop convention for chat apps.
                      onSubmitted: (_) => _send(),
                    ),
                  ),
                  const SizedBox(width: 4),
                  // AnimatedContainer smoothly transitions the Send button between
                  // its disabled and active states when _hasText flips.
                  AnimatedContainer(
                    duration: const Duration(milliseconds: 150),
                    child: _hasText
                        // Filled (tinted) button when there is text to send.
                        ? IconButton.filled(
                            onPressed: _send,
                            icon: const Icon(Icons.send_rounded),
                            tooltip: 'Send',
                          )
                        // Ghost button when field is empty — visually present
                        // but not interactive (onPressed: null disables it).
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

/// _ReplyPreview — the thin quoted-message strip shown above the input field.
///
/// Mirrors common messaging-app convention: a coloured vertical bar on the
/// left, the original sender's name, a truncated preview of the message text,
/// and an × button to cancel the reply.  Spec §10.3.2 (threaded replies).
class _ReplyPreview extends StatelessWidget {
  const _ReplyPreview({required this.message, this.onCancel});

  /// The message being replied to.
  final MessageModel message;

  /// Called when the user taps × to cancel the reply context.
  /// Null-safe: the × is still rendered but tapping it is a no-op if null.
  final VoidCallback? onCancel;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final ts = Theme.of(context).textTheme;
    return Container(
      padding: const EdgeInsets.only(left: 16, right: 8, top: 8, bottom: 4),
      decoration: BoxDecoration(
        // Hairline bottom border visually separates the preview from the input.
        border: Border(bottom: BorderSide(color: cs.outlineVariant, width: 0.5)),
      ),
      child: Row(
        children: [
          // 3 px wide coloured accent bar — the visual "quoting" affordance.
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
                // Sender name in primary colour to make it visually distinct.
                Text(
                  message.sender,
                  style: ts.labelSmall?.copyWith(
                    color: cs.primary,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                // Truncated message preview — maxLines: 1 + ellipsis prevents
                // long messages from expanding the composer bar too tall.
                Text(
                  message.text,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: ts.bodySmall?.copyWith(color: cs.onSurfaceVariant),
                ),
              ],
            ),
          ),
          // Cancel button — compact 32×32 hit area to avoid accidental taps.
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
