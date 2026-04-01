import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../backend/backend_bridge.dart';
import '../../core/widgets/empty_state.dart';
import '../../app/app_theme.dart';

class GardenFeedScreen extends StatefulWidget {
  const GardenFeedScreen({super.key});
  @override
  State<GardenFeedScreen> createState() => _GardenFeedScreenState();
}

class _GardenFeedScreenState extends State<GardenFeedScreen> {
  List<Map<String, dynamic>> _posts = const [];
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final bridge = context.read<BackendBridge>();
    final posts = bridge.fetchGardenPosts('');
    if (mounted) setState(() { _posts = posts; _loading = false; }); 
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());
    if (_posts.isEmpty) {
      return const EmptyState(
        icon: Icons.dynamic_feed_outlined,
        title: 'Nothing in your feed yet',
        body: 'Posts from gardens you join will appear here.',
      );
    }
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.separated(
        padding: const EdgeInsets.symmetric(vertical: 8),
        itemCount: _posts.length,
        separatorBuilder: (_, _) =>
            const Divider(height: 1, indent: 16, endIndent: 16),
        itemBuilder: (context, i) => _PostTile(post: _posts[i]),
      ),
    );
  }
}

class _PostTile extends StatelessWidget {
  const _PostTile({required this.post});
  final Map<String, dynamic> post;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;
    final authorName = post['authorName'] as String? ?? 'Unknown';
    final content    = post['content']    as String? ?? '';
    final reactions  = (post['reactionCount'] as num?)?.toInt() ?? 0;
    final ts         = post['timestamp']  as int?;

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(children: [
            CircleAvatar(
              radius: 16,
              backgroundColor: MeshTheme.brand.withValues(alpha: 0.15),
              child: Text(
                authorName.isNotEmpty ? authorName[0].toUpperCase() : '?',
                style: const TextStyle(
                  fontSize: 13, fontWeight: FontWeight.w700,
                  color: MeshTheme.brand,
                ),
              ),
            ),
            const SizedBox(width: 10),
            Expanded(child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(authorName, style: theme.textTheme.titleSmall),
                if (ts != null)
                  Text(_formatTs(ts),
                    style: theme.textTheme.bodySmall
                        ?.copyWith(color: cs.onSurfaceVariant)),
              ],
            )),
          ]),
          const SizedBox(height: 10),
          Text(content, style: theme.textTheme.bodyMedium),
          if (reactions > 0) ...[
            const SizedBox(height: 8),
            Text('$reactions reaction${reactions == 1 ? '' : 's'}',
              style: theme.textTheme.bodySmall
                  ?.copyWith(color: cs.onSurfaceVariant)),
          ],
        ],
      ),
    );
  }

  String _formatTs(int epochSeconds) {
    final dt = DateTime.fromMillisecondsSinceEpoch(epochSeconds * 1000);
    final diff = DateTime.now().difference(dt);
    if (diff.inMinutes < 1) return 'Just now';
    if (diff.inHours < 1)   return '${diff.inMinutes}m ago';
    if (diff.inDays < 1)    return '${diff.inHours}h ago';
    if (diff.inDays < 7)    return '${diff.inDays}d ago';
    return '${dt.day}/${dt.month}/${dt.year}';
  }
}
