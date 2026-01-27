import 'package:flutter/material.dart';

import '../../backend/thread_store.dart';
import '../../core/layout/layout_spec.dart';
import '../../models/thread_models.dart';
import 'widgets/composer_bar.dart';
import 'widgets/conversation_list.dart';
import 'widgets/top_bar.dart';
import 'widgets/thread_sidebar.dart';

class SignalShell extends StatefulWidget {
  const SignalShell({super.key});

  @override
  State<SignalShell> createState() => _SignalShellState();
}

class _SignalShellState extends State<SignalShell> {
  final TextEditingController _composer = TextEditingController();
  late final ThreadStore _store;

  @override
  void initState() {
    super.initState();
    _store = ThreadStore();
    _store.initialize();
  }

  @override
  void dispose() {
    _composer.dispose();
    _store.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _store,
      builder: (context, _) {
        return LayoutBuilder(
          builder: (context, constraints) {
            final layout = LayoutSpec.resolve(constraints);
            final threads = _store.threads;
            final activeThread = _resolveActiveThread(threads, _store.activeThreadId);
            final activeMessages = _store.activeMessages;
            final hasActiveThread = activeThread != null;

            return Scaffold(
              body: SafeArea(
                child: Row(
                  children: [
                    if (layout.showSidebar)
                      SizedBox(
                        width: layout.sidebarWidth,
                        child: ThreadSidebar(
                          threads: threads,
                          activeThreadId: _store.activeThreadId,
                          onSelectThread: _store.selectThread,
                        ),
                      ),
                    Expanded(
                      child: Column(
                        children: [
                          TopBar(
                            title: activeThread?.title ?? 'NetInfinity',
                            subtitle: hasActiveThread
                                ? 'End-to-end encrypted · P2P mesh'
                                : 'Create a conversation to start messaging',
                            showMenu: !layout.showSidebar,
                            onMenuTap: () => Scaffold.of(context).openDrawer(),
                          ),
                          Expanded(
                            child: hasActiveThread
                                ? ConversationList(
                                    messages: activeMessages,
                                    padding: layout.contentPadding,
                                  )
                                : _EmptyState(
                                    onCreate: _promptCreateThread,
                                    padding: layout.contentPadding,
                                  ),
                          ),
                          ComposerBar(
                            controller: _composer,
                            padding: layout.contentPadding,
                            onAdd: _promptCreateThread,
                            onSend: _handleSend,
                            enabled: hasActiveThread,
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
              drawer: layout.showSidebar
                  ? null
                  : Drawer(
                      child: ThreadSidebar(
                        threads: threads,
                        activeThreadId: _store.activeThreadId,
                        onSelectThread: (threadId) {
                          Navigator.pop(context);
                          _store.selectThread(threadId);
                        },
                      ),
                    ),
            );
          },
        );
      },
    );
  }

  ThreadSummary? _resolveActiveThread(List<ThreadSummary> threads, String? activeId) {
    if (threads.isEmpty) {
      return null;
    }
    if (activeId == null) {
      return threads.first;
    }
    return threads.firstWhere(
      (thread) => thread.id == activeId,
      orElse: () => threads.first,
    );
  }

  Future<void> _promptCreateThread() async {
    final controller = TextEditingController();
    final name = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('New conversation'),
        content: TextField(
          controller: controller,
          autofocus: true,
          decoration: const InputDecoration(hintText: 'Conversation name'),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, controller.text),
            child: const Text('Create'),
          ),
        ],
      ),
    );
    controller.dispose();
    if (name == null) {
      return;
    }
    final trimmed = name.trim();
    if (trimmed.isEmpty) {
      return;
    }
    await _store.createThread(trimmed);
  }

  void _handleSend(String text) {
    if (text.trim().isEmpty) {
      return;
    }
    _store.sendMessage(text);
    _composer.clear();
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState({required this.onCreate, required this.padding});

  final VoidCallback onCreate;
  final double padding;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: EdgeInsets.all(padding),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.forum_outlined, size: 48, color: Color(0xFF9AA4AF)),
            const SizedBox(height: 12),
            const Text(
              'No conversations yet',
              style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
            ),
            const SizedBox(height: 6),
            const Text(
              'Create a conversation to start exchanging keys and messages.',
              textAlign: TextAlign.center,
              style: TextStyle(color: Color(0xFF7B8188)),
            ),
            const SizedBox(height: 16),
            FilledButton.icon(
              onPressed: onCreate,
              icon: const Icon(Icons.add_comment_outlined),
              label: const Text('New conversation'),
            ),
          ],
        ),
      ),
    );
  }
}
