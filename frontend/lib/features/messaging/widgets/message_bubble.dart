import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../../backend/models/message_models.dart';

/// MessageBubble — renders a single message in a chat thread.
///
/// Layout follows the standard messenger convention:
///   - Outgoing messages (sent by us) align right with [primaryContainer] fill.
///   - Incoming messages align left with [surfaceContainerHighest] fill.
///   - The "chat bubble tail" is formed by giving the bottom-[near] corner a
///     tight 4 dp radius while the bottom-[far] corner stays at 18 dp —
///     visually pointing toward the sender's side.
///
/// The bubble displays, in order from top to bottom:
///   1. Forwarded-from label (if [message.forwardedFrom] is non-null).
///   2. Quoted reply preview (if [message.replyTo] is non-null).
///   3. Sender name (incoming messages only — outgoing sender is implicit).
///   4. Message body text.
///   5. Decryption-failure warning (§M17) — shown instead of garbled text.
///   6. Timestamp + "edited" tag + delivery status icon.
///   7. Emoji reaction chips.
///
/// Long-press opens a context menu (reply, react, edit, delete, forward, copy).
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

  /// The message to display.
  final MessageModel message;

  /// Called to delete the message locally (only removes from this device's store).
  /// Null hides the "Delete locally" option in the context menu.
  final VoidCallback? onDelete;

  /// Called when the user selects "Reply" from the context menu.
  final VoidCallback? onReply;

  /// Called with the chosen emoji when the user picks a reaction.
  final ValueChanged<String>? onReact;

  /// Called when the user chooses to edit the message text.
  /// Only offered for outgoing messages (we can only edit our own).
  final VoidCallback? onEdit;

  /// Called to request deletion for all participants.
  /// Only offered for outgoing messages; shows a confirmation dialog first.
  final VoidCallback? onDeleteForEveryone;

  /// Called to forward the message to another room or contact.
  final VoidCallback? onForward;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final isOutgoing = message.isOutgoing;

    final bubble = GestureDetector(
      onLongPress: () => _showContextMenu(context),
      child: Container(
        // Cap bubble width at 72% of screen width.  Very wide bubbles make
        // text hard to read; too narrow wastes space on large screens.
        constraints: BoxConstraints(
          maxWidth: MediaQuery.sizeOf(context).width * 0.72,
        ),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        decoration: BoxDecoration(
          // Outgoing: brand tinted background.  Incoming: neutral surface.
          color: isOutgoing ? cs.primaryContainer : cs.surfaceContainerHighest,
          borderRadius: BorderRadius.only(
            topLeft: const Radius.circular(18),
            topRight: const Radius.circular(18),
            // The "tail" is the tight corner on the sender's side.  Outgoing
            // messages point right (bottomRight tight), incoming point left
            // (bottomLeft tight).
            bottomLeft: Radius.circular(isOutgoing ? 18 : 4),
            bottomRight: Radius.circular(isOutgoing ? 4 : 18),
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // ── Forwarded label ────────────────────────────────────────
            // Only shown when the message was forwarded from another room.
            // Displayed in muted italic to signal secondary provenance.
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
            // ── Quoted reply preview ───────────────────────────────────
            // Shows a bordered snippet of the parent message so the reader
            // understands the context of this reply (§10.3.2).
            if (message.replyTo != null) ...[
              Container(
                padding: const EdgeInsets.only(left: 8, bottom: 4),
                decoration: BoxDecoration(
                  // Left accent bar — the visual "quoting" affordance.
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
            // ── Sender name ────────────────────────────────────────────
            // Shown for incoming messages only.  In a group conversation the
            // recipient needs to know who sent each message; for outgoing
            // messages the alignment already communicates authorship.
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
            // ── Message body ──────────────────────────────────────────
            // Color contrast differs between outgoing (on primaryContainer)
            // and incoming (on surface) to maintain legibility.
            Text(
              message.text,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: isOutgoing ? cs.onPrimaryContainer : cs.onSurface,
              ),
            ),
            // ── Decryption failure warning ─────────────────────────────
            // §M17: when decryption fails we MUST NOT display garbled
            // ciphertext as if it were readable content.  The ⚠ badge
            // signals that the message payload could not be authenticated
            // and should not be trusted.  The raw encrypted bytes are
            // hidden; `message.text` in this case holds a placeholder.
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
            // ── Timestamp row ──────────────────────────────────────────
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  _formatTime(message.timestamp),
                  style: Theme.of(context).textTheme.labelSmall?.copyWith(
                    // 60% opacity to visually subordinate metadata vs body.
                    color: (isOutgoing ? cs.onPrimaryContainer : cs.onSurface)
                        .withValues(alpha: 0.6),
                  ),
                ),
                // "edited" tag — shown when the sender has changed the
                // message after it was originally delivered.
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
                // Delivery status icon — shown on outgoing messages only,
                // and suppressed if the status is the bare "sent" state
                // (no extra icon needed; timestamp alone implies sent).
                if (isOutgoing && message.deliveryStatus != 'sent') ...[
                  const SizedBox(width: 4),
                  _DeliveryIcon(status: message.deliveryStatus, color:
                    (cs.onPrimaryContainer).withValues(alpha: 0.6)),
                ],
              ],
            ),
            // ── Reaction chips ─────────────────────────────────────────
            // Each unique emoji is shown once with its count.  The
            // `_groupReactions` helper de-duplicates and counts.
            if (message.reactions.isNotEmpty) ...[
              const SizedBox(height: 4),
              Wrap(
                spacing: 4,
                runSpacing: 2,
                children: _groupReactions(message.reactions).entries.map((e) {
                  return Container(
                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      // Neutral chip background — reuses the surface colour so
                      // chips on both outgoing and incoming bubbles look consistent.
                      color: cs.surfaceContainerHighest,
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Text(
                      // Format: "👍 3" — emoji then count.
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

    // Align the bubble to the right for outgoing, left for incoming.
    // Horizontal padding gives breathing room against the screen edge.
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 3),
      child: Align(
        alignment: isOutgoing ? Alignment.centerRight : Alignment.centerLeft,
        child: bubble,
      ),
    );
  }

  /// Collapses the flat reaction list into a map of {emoji → count}.
  ///
  /// Multiple reactions with the same emoji from different users are combined
  /// so we display "👍 3" rather than three separate "👍" chips.
  Map<String, int> _groupReactions(List<ReactionModel> reactions) {
    final counts = <String, int>{};
    for (final r in reactions) {
      counts[r.emoji] = (counts[r.emoji] ?? 0) + 1;
    }
    return counts;
  }

  /// Parses an ISO 8601 timestamp and returns a "HH:mm" local-time string.
  ///
  /// Returns an empty string rather than throwing if the timestamp is missing
  /// or malformed — a blank time stamp is better than a crash.  The try/catch
  /// silences parse errors because we can't control what the backend might
  /// send for historical messages migrated from older database rows.
  String _formatTime(String iso) {
    try {
      final dt = DateTime.parse(iso).toLocal();
      // Zero-pad hours and minutes to always produce "HH:mm" format.
      final h = dt.hour.toString().padLeft(2, '0');
      final m = dt.minute.toString().padLeft(2, '0');
      return '$h:$m';
    } catch (_) {
      // Swallowed: a malformed or empty timestamp must not crash the list.
      // Returning empty string means the time slot shows nothing, which is
      // acceptable; the message body is still readable.
      return '';
    }
  }

  /// Shows a bottom-sheet context menu with actions relevant to this message.
  ///
  /// Edit and "Delete for everyone" are only offered for outgoing messages —
  /// we cannot edit or remotely delete messages sent by other users.
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
                // Open the emoji picker in a second bottom sheet.
                _showEmojiPicker(context);
              },
            ),
            // Edit — only available on our own messages.
            if (message.isOutgoing)
              ListTile(
                leading: const Icon(Icons.edit_outlined),
                title: const Text('Edit'),
                onTap: () {
                  Navigator.pop(ctx);
                  onEdit?.call();
                },
              ),
            // "Delete for everyone" — only available on our own messages.
            // Requires a confirmation dialog because the action is destructive
            // and cannot be undone on the recipient's device.
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
                // Write the plain message text to the system clipboard.
                Clipboard.setData(ClipboardData(text: message.text));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Copied to clipboard'),
                    duration: Duration(seconds: 2),
                  ),
                );
              },
            ),
            // "Delete locally" — only shown when a delete callback is provided.
            // This removes the message from this device's store without
            // notifying the other party (unlike "Delete for everyone").
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

  /// Shows a quick-pick emoji sheet with the 16 most common reaction emojis.
  ///
  /// A full emoji keyboard would require a third-party package and adds
  /// significant binary size; this curated set covers the vast majority of
  /// real-world reactions.  Unicode escape sequences are used so the source
  /// file stays ASCII-clean.
  void _showEmojiPicker(BuildContext context) {
    const commonEmojis = [
      '\u{1F44D}', // 👍
      '\u{2764}',  // ❤
      '\u{1F602}', // 😂
      '\u{1F62E}', // 😮
      '\u{1F622}', // 😢
      '\u{1F64F}', // 🙏
      '\u{1F525}', // 🔥
      '\u{1F389}', // 🎉
      '\u{1F44F}', // 👏
      '\u{1F914}', // 🤔
      '\u{1F60D}', // 😍
      '\u{1F621}', // 😡
      '\u{1F60A}', // 😊
      '\u{1F973}', // 🥳
      '\u{1F4AF}', // 💯
      '\u{2705}',  // ✅
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
                      // Emit the chosen emoji to the caller, which will send
                      // the reaction event to the backend.
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

  /// Shows a confirmation dialog before requesting remote deletion.
  ///
  /// Remote deletion propagates a "delete" signal to all participants' clients.
  /// It is irreversible from this device — hence the explicit confirmation step.
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
            // Error colour reinforces that the action is destructive.
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

/// _DeliveryIcon — a tiny status icon shown on outgoing messages.
///
/// Maps the backend delivery-status string to a visual indicator:
///   "sending"   → clock icon   (in transit, not yet acknowledged)
///   "delivered" → double-tick  (arrived on at least one server/relay)
///   "read"      → double-tick in primary colour (recipient has opened it)
///   "failed"    → error icon   (delivery failed; user should retry)
///   (default)   → single tick  (sent but no further info)
///
/// The "read" state uses the primary colour to match common messenger
/// conventions (WhatsApp blue ticks, etc.) and distinguish it from "delivered".
class _DeliveryIcon extends StatelessWidget {
  const _DeliveryIcon({required this.status, required this.color});

  /// One of: "sending", "delivered", "read", "failed", or any custom string.
  final String status;

  /// Base colour for all states except "read" (which uses primary colour).
  final Color color;

  @override
  Widget build(BuildContext context) {
    final icon = switch (status) {
      'sending'   => Icons.schedule,      // Clock: still in flight.
      'delivered' => Icons.done_all,      // Double tick: arrived at relay.
      'read'      => Icons.done_all,      // Double tick: recipient saw it.
      'failed'    => Icons.error_outline, // Error ring: delivery failed.
      _           => Icons.done,          // Single tick: sent from this device.
    };
    return Icon(
      icon,
      size: 14,
      // "read" uses the primary brand colour; all other statuses use the
      // muted colour passed in from the bubble's text-colour stack.
      color: status == 'read'
          ? Theme.of(context).colorScheme.primary
          : color,
    );
  }
}
