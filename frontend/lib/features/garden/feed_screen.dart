// feed_screen.dart
//
// GardenFeedScreen is sub-page 1 of the Garden section.
// It displays a chronological feed of posts from all gardens the user has
// joined — similar in concept to a social-media timeline, but fully local
// to the mesh.
//
// WHAT IS A "POST"?
// -----------------
// A post is a longer-form content item published to a garden.  Unlike chat
// messages (short, ephemeral), posts are intended for announcements,
// articles, or community updates that should be easy to scroll back through.
// Posts are backed by the same backend room/message infrastructure as chat,
// but the garden layer adds author metadata, reaction counts, and garden
// context to each item.
//
// DATA MODEL (raw backend map)
// ----------------------------
// Each post map is expected to contain:
//   authorName    — display name of the poster (String)
//   gardenName    — name of the garden the post belongs to (String, may be empty)
//   content       — body text of the post (String)
//   reactionCount — total reactions on the post (int)
//   timestamp     — Unix epoch seconds of publication (int)
//
// The backend currently returns posts across all joined gardens in a single
// flat list.  A future version may support per-garden filtering.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../backend/backend_bridge.dart';
// BackendBridge — all FFI calls, including fetchGardenPosts().
import '../../core/widgets/empty_state.dart';
// EmptyState — shared zero-data placeholder widget.
import '../../app/app_theme.dart';
// MeshTheme.brand — brand colour used for the author avatar tint.

/// Aggregated post feed from all gardens the user has joined.
///
/// Loaded on mount; refreshable via pull-to-refresh.
class GardenFeedScreen extends StatefulWidget {
  const GardenFeedScreen({super.key});
  @override
  State<GardenFeedScreen> createState() => _GardenFeedScreenState();
}

class _GardenFeedScreenState extends State<GardenFeedScreen> {
  // ---------------------------------------------------------------------------
  // State fields
  // ---------------------------------------------------------------------------

  /// The posts returned by the backend.  Starts empty; populated by _load().
  List<Map<String, dynamic>> _posts = const [];

  /// True while _load() is running — shows a full-screen spinner.
  bool _loading = true;

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  @override
  void initState() {
    super.initState();
    // Load posts immediately so the screen is populated on first render.
    _load();
  }

  // ---------------------------------------------------------------------------
  // Data loading
  // ---------------------------------------------------------------------------

  /// Fetches the aggregated post feed from the backend.
  ///
  /// The empty-string argument to fetchGardenPosts means "all gardens" — a
  /// future parameter could be a specific gardenId for per-garden filtering.
  ///
  /// The [mounted] guard before setState prevents a "setState after dispose"
  /// error if the user navigates away during the (synchronous) FFI call.
  Future<void> _load() async {
    final bridge = context.read<BackendBridge>();
    // Empty-string gardenId = fetch posts from all joined gardens.
    final posts = bridge.fetchGardenPosts('');
    if (mounted) {
      setState(() {
        _posts = posts;
        _loading = false;
      });
    }
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());

    // Empty state — user has joined no gardens, or those gardens have no posts.
    if (_posts.isEmpty) {
      return const EmptyState(
        icon: Icons.dynamic_feed_outlined,
        title: 'Nothing in your feed yet',
        body: 'Posts from gardens you join will appear here.',
      );
    }

    // Non-empty: vertically separated list of post tiles.
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.separated(
        padding: const EdgeInsets.symmetric(vertical: 8),
        itemCount: _posts.length,
        // Thin divider between posts — indented 16px on both sides to align
        // with the content padding rather than going edge-to-edge.
        separatorBuilder: (_, _) =>
            const Divider(height: 1, indent: 16, endIndent: 16),
        itemBuilder: (context, i) => _PostTile(post: _posts[i]),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _PostTile — one post entry in the feed
// ---------------------------------------------------------------------------

/// Renders a single garden post: author avatar, name, timestamp, body text,
/// and a reaction count (when > 0).
///
/// Intentionally stateless — all data comes from the [post] map.
class _PostTile extends StatelessWidget {
  const _PostTile({required this.post});

  /// The raw post map from the backend.
  final Map<String, dynamic> post;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    // Parse all fields with null-safe casts so a stale or partial backend
    // record does not crash the UI.
    final authorName = post['authorName'] as String? ?? 'Unknown';
    final gardenName = post['gardenName'] as String? ?? '';
    final content    = post['content']    as String? ?? '';
    final reactions  = (post['reactionCount'] as num?)?.toInt() ?? 0;

    // timestamp is an int? — it may be absent from older backend records
    // (pre-timestamp posts).  The _formatTs helper treats 0 as "just now"
    // which is a reasonable fallback.
    final ts = post['timestamp'] as int?;

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Author row: avatar | name | timestamp (+ garden name if provided).
          Row(children: [
            // Author avatar — initial letter on a brand-tinted circle.
            // Falls back to '?' for empty author names (e.g. anonymous posts).
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

            // Author name + timestamp on two lines.
            Expanded(child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(authorName, style: theme.textTheme.titleSmall),
                // Show timestamp (prefixed by garden name if available).
                // The (ts ?? 0) fallback maps a missing timestamp to epoch 0,
                // which _formatTs will render as "Just now" — acceptable
                // until the backend guarantees timestamp presence.
                if (gardenName.isNotEmpty || ts != null)
                  Text(_formatTs(ts ?? 0),
                    style: theme.textTheme.bodySmall
                        ?.copyWith(color: cs.onSurfaceVariant)),
              ],
            )),
          ]),
          const SizedBox(height: 10),

          // Post body text — no truncation so the full content is visible.
          Text(content, style: theme.textTheme.bodyMedium),

          // Reaction count — only shown when at least one reaction exists.
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

  /// Formats an epoch-seconds timestamp as a human-readable relative string.
  ///
  /// Prepends the garden name (if non-empty) so the user knows which
  /// community the post belongs to when scrolling through a mixed feed.
  ///
  /// Ranges:
  ///   < 1 minute  → "Just now"
  ///   < 1 hour    → "Xm ago"
  ///   < 1 day     → "Xh ago"
  ///   < 7 days    → "Xd ago"
  ///   ≥ 7 days    → "DD/MM/YYYY" absolute date
  String _formatTs(int epochSeconds) {
    // Re-read gardenName from the post map so _formatTs stays a pure helper
    // without needing extra parameters.
    final gardenName = post['gardenName'] as String? ?? '';

    // Convert epoch seconds to a DateTime for diff calculations.
    final dt = DateTime.fromMillisecondsSinceEpoch(epochSeconds * 1000);
    final diff = DateTime.now().difference(dt);

    late final String timeLabel;
    if (diff.inMinutes < 1) {
      timeLabel = 'Just now';
    } else if (diff.inHours < 1) {
      timeLabel = '${diff.inMinutes}m ago';
    } else if (diff.inDays < 1) {
      timeLabel = '${diff.inHours}h ago';
    } else if (diff.inDays < 7) {
      timeLabel = '${diff.inDays}d ago';
    } else {
      // Older than a week: show the absolute date (day/month/year).
      timeLabel = '${dt.day}/${dt.month}/${dt.year}';
    }

    // If we know which garden this post is from, prefix the timestamp with
    // the garden name so the user can tell at a glance which community it
    // belongs to in the aggregated feed.
    if (gardenName.isEmpty) return timeLabel;
    return '$gardenName · $timeLabel';
  }
}
