import 'package:flutter/material.dart';

import '../../../models/thread_models.dart';

class ThreadSidebar extends StatelessWidget {
  const ThreadSidebar({
    super.key,
    required this.threads,
    required this.activeThreadId,
    required this.onSelectThread,
  });

  final List<ThreadSummary> threads;
  final String? activeThreadId;
  final ValueChanged<String> onSelectThread;

  @override
  Widget build(BuildContext context) {
    return Container(
      color: Colors.white,
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          const Text('Conversations', style: TextStyle(fontSize: 12, color: Color(0xFF93A1AE))),
          const SizedBox(height: 12),
          if (threads.isEmpty)
            const Padding(
              padding: EdgeInsets.symmetric(vertical: 16),
              child: Text('No conversations yet', style: TextStyle(color: Color(0xFF7B8188))),
            ),
          ...threads.map(
            (thread) => _ThreadTile(
              thread: thread,
              selected: activeThreadId != null && thread.id == activeThreadId,
              onTap: () => onSelectThread(thread.id),
            ),
          ),
          const SizedBox(height: 24),
          const Text('Network', style: TextStyle(fontSize: 12, color: Color(0xFF93A1AE))),
          const SizedBox(height: 8),
          ListTile(
            title: const Text('Trusted peers'),
            subtitle: const Text('12 active'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () {},
          ),
          ListTile(
            title: const Text('Safety numbers'),
            subtitle: const Text('Verify identities'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () {},
          ),
          ListTile(
            title: const Text('Key bundles'),
            subtitle: const Text('Sync over mesh'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () {},
          ),
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
    return Card(
      elevation: 0,
      color: selected ? const Color(0xFFE8EEF9) : const Color(0xFFF7F8FA),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: ListTile(
        leading: CircleAvatar(
          backgroundColor: selected ? const Color(0xFF2C6EE2) : const Color(0xFF9AA4AF),
          child: Text(
            thread.title.isNotEmpty ? thread.title.substring(0, 1) : '?',
            style: const TextStyle(color: Colors.white),
          ),
        ),
        title: Text(thread.title, style: const TextStyle(fontWeight: FontWeight.w600)),
        subtitle: Text(thread.preview, maxLines: 1, overflow: TextOverflow.ellipsis),
        trailing: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          crossAxisAlignment: CrossAxisAlignment.end,
          children: [
            Text(thread.lastSeen, style: const TextStyle(fontSize: 11, color: Color(0xFF7B8188))),
            if (thread.unreadCount > 0)
              Container(
                margin: const EdgeInsets.only(top: 4),
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: const Color(0xFF2C6EE2),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Text(
                  '${thread.unreadCount}',
                  style: const TextStyle(color: Colors.white, fontSize: 10),
                ),
              ),
          ],
        ),
        onTap: onTap,
      ),
    );
  }
}
