import 'package:flutter/material.dart';

import '../../../models/thread_models.dart';
import '../../menu/menu_models.dart';

class ThreadSidebar extends StatelessWidget {
  const ThreadSidebar({
    super.key,
    required this.threads,
    required this.activeThreadId,
    required this.activeSection,
    required this.onSelectThread,
    required this.onCreateThread,
    required this.onSelectSection,
    this.pairingCode,
    this.footer,
  });

  final List<ThreadSummary> threads;
  final String? activeThreadId;
  final GlobalMenuSection activeSection;
  final ValueChanged<String> onSelectThread;
  final VoidCallback onCreateThread;
  final ValueChanged<GlobalMenuSection> onSelectSection;
  final String? pairingCode;
  final Widget? footer;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Container(
      color: cs.surface,
      child: Column(
        children: [
          // Header: title + create button
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 16, 8, 4),
            child: Row(
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Conversations',
                        style: Theme.of(context).textTheme.titleMedium
                            ?.copyWith(fontWeight: FontWeight.w600),
                      ),
                      if (pairingCode != null && pairingCode!.isNotEmpty)
                        SelectableText(
                          pairingCode!,
                          style: Theme.of(context).textTheme.bodySmall
                              ?.copyWith(color: cs.onSurfaceVariant),
                        ),
                    ],
                  ),
                ),
                IconButton(
                  onPressed: onCreateThread,
                  icon: const Icon(Icons.add_circle_outline),
                ),
              ],
            ),
          ),
          const Divider(height: 1),
          // Thread list
          Expanded(
            child: threads.isEmpty
                ? Center(
                    child: Padding(
                      padding: const EdgeInsets.all(24),
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(
                            Icons.chat_bubble_outline,
                            size: 40,
                            color: cs.onSurfaceVariant,
                          ),
                          const SizedBox(height: 8),
                          Text(
                            'No conversations',
                            style: TextStyle(color: cs.onSurfaceVariant),
                          ),
                        ],
                      ),
                    ),
                  )
                : ListView.builder(
                    padding: const EdgeInsets.symmetric(
                      vertical: 4,
                      horizontal: 8,
                    ),
                    itemCount: threads.length,
                    itemBuilder: (context, i) {
                      final thread = threads[i];
                      return _ThreadTile(
                        thread: thread,
                        selected: thread.id == activeThreadId,
                        onTap: () => onSelectThread(thread.id),
                      );
                    },
                  ),
          ),
          if (footer != null) ...[const Divider(height: 1), footer!],
        ],
      ),
    );
  }
}

class _ThreadTile extends StatelessWidget {
  const _ThreadTile({
    required this.thread,
    required this.selected,
    required this.onTap,
  });

  final ThreadSummary thread;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final hasUnread = thread.unreadCount > 0;

    return ListTile(
      contentPadding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      selected: selected,
      selectedColor: cs.onSurfaceVariant,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      onTap: onTap,
      leading: CircleAvatar(
        radius: 22,
        backgroundColor: _avatarColor(thread.title),
        child: Text(
          thread.title.isNotEmpty ? thread.title[0].toUpperCase() : '?',
          style: const TextStyle(
            color: Colors.white,
            fontWeight: FontWeight.w600,
            fontSize: 16,
          ),
        ),
      ),
      title: Text(
        thread.title,
        style: Theme.of(context).textTheme.bodyLarge?.copyWith(
          fontWeight: hasUnread ? FontWeight.w600 : FontWeight.normal,
        ),
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
      ),
      subtitle: Text(
        thread.preview,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: TextStyle(color: cs.onSurfaceVariant),
      ),
      trailing: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          Text(
            thread.lastSeen,
            style: Theme.of(
              context,
            ).textTheme.bodySmall?.copyWith(color: cs.onSurfaceVariant),
          ),
          if (hasUnread) ...[
            const SizedBox(height: 4),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
              decoration: BoxDecoration(
                color: cs.primary,
                borderRadius: BorderRadius.circular(10),
              ),
              child: Text(
                thread.unreadCount.toString(),
                style: TextStyle(
                  color: cs.onPrimary,
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }
}

Color _avatarColor(String name) {
  int hash = 0;
  for (final c in name.codeUnits) {
    hash = ((hash << 5) - hash) + c;
    hash = hash & 0x7FFFFFFF;
  }
  const palette = [
    Color(0xFF1ABC9C),
    Color(0xFFE74C3C),
    Color(0xFF9B59B6),
    Color(0xFFE67E22),
    Color(0xFF3498DB),
    Color(0xFF2ECC71),
    Color(0xFFE91E63),
    Color(0xFF607D8B),
  ];
  return palette[hash % palette.length];
}
