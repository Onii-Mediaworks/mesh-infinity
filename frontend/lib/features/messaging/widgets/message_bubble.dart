import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../../backend/models/message_models.dart';

class MessageBubble extends StatelessWidget {
  const MessageBubble({
    super.key,
    required this.message,
    this.onDelete,
    this.onReply,
    this.onReact,
    this.onEdit,
    this.onDeleteForEveryone,
    this.onForward,
  });

  final MessageModel message;
  final VoidCallback? onDelete;
  final VoidCallback? onReply;
  final ValueChanged<String>? onReact;
  final VoidCallback? onEdit;
  final VoidCallback? onDeleteForEveryone;
  final VoidCallback? onForward;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final isOutgoing = message.isOutgoing;

    final bubble = GestureDetector(
      onLongPress: () => _showContextMenu(context),
      child: Container(
        constraints: BoxConstraints(
          maxWidth: MediaQuery.sizeOf(context).width * 0.72,
        ),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        decoration: BoxDecoration(
          color: isOutgoing ? cs.primaryContainer : cs.surfaceContainerHighest,
          borderRadius: BorderRadius.only(
            topLeft: const Radius.circular(18),
            topRight: const Radius.circular(18),
            bottomLeft: Radius.circular(isOutgoing ? 18 : 4),
            bottomRight: Radius.circular(isOutgoing ? 4 : 18),
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (message.forwardedFrom != null) ...[
              Text(
                'Forwarded',
                style: Theme.of(context).textTheme.labelSmall?.copyWith(
                  color: cs.outline,
                  fontStyle: FontStyle.italic,
                ),
              ),
              const SizedBox(height: 2),
            ],
            if (message.replyTo != null) ...[
              Container(
                padding: const EdgeInsets.only(left: 8, bottom: 4),
                decoration: BoxDecoration(
                  border: Border(
                    left: BorderSide(color: cs.primary, width: 2),
                  ),
                ),
                child: Text(
                  message.replyTo!,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: cs.outline,
                  ),
                ),
              ),
              const SizedBox(height: 4),
            ],
            if (!isOutgoing) ...[
              Text(
                message.sender,
                style: Theme.of(context).textTheme.labelSmall?.copyWith(
                  color: cs.primary,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 2),
            ],
            Text(
              message.text,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: isOutgoing ? cs.onPrimaryContainer : cs.onSurface,
              ),
            ),
            // M17: Show decryption failure warning — never display raw ciphertext
            // as readable content. The ⚠ badge signals the message is untrustworthy.
            if (message.isDecryptionFailed) ...[
              const SizedBox(height: 4),
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.warning_amber_rounded, size: 14, color: cs.error),
                  const SizedBox(width: 4),
                  Text(
                    'Decryption failed',
                    style: Theme.of(context).textTheme.labelSmall?.copyWith(
                      color: cs.error,
                    ),
                  ),
                ],
              ),
            ],
            const SizedBox(height: 4),
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  _formatTime(message.timestamp),
                  style: Theme.of(context).textTheme.labelSmall?.copyWith(
                    color: (isOutgoing ? cs.onPrimaryContainer : cs.onSurface)
                        .withValues(alpha: 0.6),
                  ),
                ),
                if (message.edited) ...[
                  const SizedBox(width: 4),
                  Text(
                    'edited',
                    style: Theme.of(context).textTheme.labelSmall?.copyWith(
                      color: (isOutgoing ? cs.onPrimaryContainer : cs.onSurface)
                          .withValues(alpha: 0.5),
                      fontStyle: FontStyle.italic,
                    ),
                  ),
                ],
                if (isOutgoing && message.deliveryStatus != 'sent') ...[
                  const SizedBox(width: 4),
                  _DeliveryIcon(status: message.deliveryStatus, color:
                    (cs.onPrimaryContainer).withValues(alpha: 0.6)),
                ],
              ],
            ),
            if (message.reactions.isNotEmpty) ...[
              const SizedBox(height: 4),
              Wrap(
                spacing: 4,
                runSpacing: 2,
                children: _groupReactions(message.reactions).entries.map((e) {
                  return Container(
                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color: cs.surfaceContainerHighest,
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Text(
                      '${e.key} ${e.value}',
                      style: Theme.of(context).textTheme.labelSmall,
                    ),
                  );
                }).toList(),
              ),
            ],
          ],
        ),
      ),
    );

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 3),
      child: Align(
        alignment: isOutgoing ? Alignment.centerRight : Alignment.centerLeft,
        child: bubble,
      ),
    );
  }

  Map<String, int> _groupReactions(List<ReactionModel> reactions) {
    final counts = <String, int>{};
    for (final r in reactions) {
      counts[r.emoji] = (counts[r.emoji] ?? 0) + 1;
    }
    return counts;
  }

  String _formatTime(String iso) {
    try {
      final dt = DateTime.parse(iso).toLocal();
      final h = dt.hour.toString().padLeft(2, '0');
      final m = dt.minute.toString().padLeft(2, '0');
      return '$h:$m';
    } catch (_) {
      return '';
    }
  }

  void _showContextMenu(BuildContext context) {
    showModalBottomSheet<void>(
      context: context,
      builder: (ctx) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.reply_rounded),
              title: const Text('Reply'),
              onTap: () {
                Navigator.pop(ctx);
                onReply?.call();
              },
            ),
            ListTile(
              leading: const Icon(Icons.add_reaction_outlined),
              title: const Text('React'),
              onTap: () {
                Navigator.pop(ctx);
                _showEmojiPicker(context);
              },
            ),
            if (message.isOutgoing)
              ListTile(
                leading: const Icon(Icons.edit_outlined),
                title: const Text('Edit'),
                onTap: () {
                  Navigator.pop(ctx);
                  onEdit?.call();
                },
              ),
            if (message.isOutgoing)
              ListTile(
                leading: Icon(Icons.delete_forever_outlined, color:
                  Theme.of(context).colorScheme.error),
                title: Text('Delete for everyone', style: TextStyle(
                  color: Theme.of(context).colorScheme.error,
                )),
                onTap: () {
                  Navigator.pop(ctx);
                  _confirmDeleteForEveryone(context);
                },
              ),
            ListTile(
              leading: const Icon(Icons.forward_outlined),
              title: const Text('Forward'),
              onTap: () {
                Navigator.pop(ctx);
                onForward?.call();
              },
            ),
            ListTile(
              leading: const Icon(Icons.copy_rounded),
              title: const Text('Copy text'),
              onTap: () {
                Navigator.pop(ctx);
                Clipboard.setData(ClipboardData(text: message.text));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Copied to clipboard'),
                    duration: Duration(seconds: 2),
                  ),
                );
              },
            ),
            if (onDelete != null)
              ListTile(
                leading: const Icon(Icons.delete_outline),
                title: const Text('Delete locally'),
                onTap: () {
                  Navigator.pop(ctx);
                  onDelete?.call();
                },
              ),
          ],
        ),
      ),
    );
  }

  void _showEmojiPicker(BuildContext context) {
    const commonEmojis = [
      '\u{1F44D}', '\u{2764}', '\u{1F602}', '\u{1F62E}', '\u{1F622}',
      '\u{1F64F}', '\u{1F525}', '\u{1F389}', '\u{1F44F}', '\u{1F914}',
      '\u{1F60D}', '\u{1F621}', '\u{1F60A}', '\u{1F973}', '\u{1F4AF}',
      '\u{2705}',
    ];
    showModalBottomSheet<void>(
      context: context,
      builder: (ctx) => SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Pick a reaction',
                style: Theme.of(context).textTheme.titleSmall,
              ),
              const SizedBox(height: 12),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: commonEmojis.map((emoji) {
                  return InkWell(
                    borderRadius: BorderRadius.circular(8),
                    onTap: () {
                      Navigator.pop(ctx);
                      onReact?.call(emoji);
                    },
                    child: Padding(
                      padding: const EdgeInsets.all(8),
                      child: Text(emoji, style: const TextStyle(fontSize: 28)),
                    ),
                  );
                }).toList(),
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _confirmDeleteForEveryone(BuildContext context) {
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Delete for everyone'),
        content: const Text(
          'This message will be permanently deleted for all participants.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () {
              Navigator.pop(ctx);
              onDeleteForEveryone?.call();
            },
            style: FilledButton.styleFrom(
              backgroundColor: Theme.of(context).colorScheme.error,
            ),
            child: const Text('Delete'),
          ),
        ],
      ),
    );
  }
}

class _DeliveryIcon extends StatelessWidget {
  const _DeliveryIcon({required this.status, required this.color});

  final String status;
  final Color color;

  @override
  Widget build(BuildContext context) {
    final icon = switch (status) {
      'sending' => Icons.schedule,
      'delivered' => Icons.done_all,
      'read' => Icons.done_all,
      'failed' => Icons.error_outline,
      _ => Icons.done,
    };
    return Icon(
      icon,
      size: 14,
      color: status == 'read'
          ? Theme.of(context).colorScheme.primary
          : color,
    );
  }
}
