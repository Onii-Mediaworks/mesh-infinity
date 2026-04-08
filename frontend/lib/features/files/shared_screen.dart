// shared_screen.dart
//
// FilesSharedScreen is the second sub-page of the Files section.
// It manages files that this device is actively *publishing* to the mesh —
// i.e. making available for other peers to download on demand.
//
// WHAT IS "PUBLISHING" A FILE?
// -----------------------------
// Publishing means the local node registers a file with the backend so that
// other mesh peers can discover it (via the service-discovery layer) and
// request a download.  The file stays on disk; the backend just tracks the
// path and metadata and serves the bytes when a peer requests them.
//
// This is different from the active-transfer flow in TransfersScreen, where
// the user explicitly pushes a file to a specific peer.  Here, the user
// announces "I have this file, whoever wants it can ask."
//
// SCREEN LAYOUT
// -------------
//   • Loading / publishing: full-screen spinner.
//   • Empty: EmptyState with a "Publish a file" call-to-action.
//   • Non-empty: scrollable list with:
//       - _StorageCard: disk usage and published-file count.
//       - "Publish another file" button.
//       - One _PublishedFileTile per published file (shows size, download count,
//         and an Unpublish button).
//
// STATE MANAGEMENT
// ----------------
// This screen owns its own async state (_stats, _files, _loading, _publishing)
// because the data is only relevant while this screen is visible.  Unlike
// transfers (which get real-time events), published files rarely change, so
// there is no need to subscribe to EventBus here.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../backend/backend_bridge.dart';
// BackendBridge — all backend calls (fetchStorageStats, fetchPublishedFiles,
// publishFile, unpublishFile) go through this gateway.
import '../../core/widgets/empty_state.dart';
// EmptyState — shared zero-data placeholder widget.
import '../../app/app_theme.dart';
// MeshTheme.brand — the primary brand colour used for the storage bar and
// the file icon tint in published file tiles.

/// Screen that lists files this device is publishing to the mesh.
///
/// Pushed from the Files section shell as sub-page index 1 (the "Shared" tab).
class FilesSharedScreen extends StatefulWidget {
  const FilesSharedScreen({super.key});
  @override
  State<FilesSharedScreen> createState() => _FilesSharedScreenState();
}

class _FilesSharedScreenState extends State<FilesSharedScreen> {
  // ---------------------------------------------------------------------------
  // State fields
  // ---------------------------------------------------------------------------

  /// Storage statistics returned by the backend (usedBytes, totalBytes,
  /// publishedFiles).  Null on initial load before data arrives.
  /// The _StorageCard widget handles the null case gracefully.
  Map<String, dynamic>? _stats;

  /// The list of currently published files.
  /// Each map has at minimum: id, name, sizeBytes, downloadCount.
  List<Map<String, dynamic>> _files = const [];

  /// True while _load() is running (shows a spinner instead of content).
  bool _loading = true;

  /// True while _promptPublishFile() is waiting for the backend to register
  /// a new file (shows a spinner and prevents concurrent publish attempts).
  bool _publishing = false;

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  @override
  void initState() {
    super.initState();
    // Load data immediately on mount so the screen is populated on first render.
    _load();
  }

  // ---------------------------------------------------------------------------
  // Data loading
  // ---------------------------------------------------------------------------

  /// Fetches storage stats and the published-file list from the backend.
  ///
  /// Both calls are synchronous FFI calls (backend returns cached data).
  /// The [mounted] guard before setState prevents calling setState on a
  /// disposed widget if the user navigated away while _load() was running.
  Future<void> _load() async {
    final bridge = context.read<BackendBridge>();
    final stats = bridge.fetchStorageStats();
    final files = bridge.fetchPublishedFiles();
    if (mounted) {
      setState(() {
        _stats = stats;
        _files = files;
        _loading = false;
      });
    }
  }

  // ---------------------------------------------------------------------------
  // Actions
  // ---------------------------------------------------------------------------

  /// Removes a file from the published list.
  ///
  /// [fileId] is the opaque ID from the backend's published-file record.
  /// On success, reloads the list so the removed tile disappears immediately.
  /// A SnackBar reports success or failure either way.
  Future<void> _unpublish(String fileId) async {
    final bridge = context.read<BackendBridge>();
    final ok = bridge.unpublishFile(fileId);
    // Reload regardless of outcome so the list is consistent with backend state.
    if (ok) await _load();
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content: Text(ok ? 'File unpublished' : 'Failed to unpublish'),
      ));
    }
  }

  /// Prompts the user for a file path via an AlertDialog, then publishes it.
  ///
  /// WHY a text field instead of FilePicker?
  /// The publish flow takes a raw filesystem path because the backend
  /// holds the path reference, not a copy of the file bytes.  FilePicker
  /// returns a path on desktop platforms but not reliably on mobile (iOS
  /// sandboxing).  The text-field approach works across all platforms.
  ///
  /// The [_publishing] flag is set while the backend call is in progress to:
  ///   1. Show a spinner so the user knows something is happening.
  ///   2. Prevent a second _promptPublishFile() call from being triggered.
  Future<void> _promptPublishFile() async {
    final controller = TextEditingController();

    // Show an AlertDialog with a text field for the file path.
    // The dialog returns the trimmed path string, or null if cancelled.
    final path = await showDialog<String>(
      context: context,
      builder: (dialogContext) {
        return AlertDialog(
          title: const Text('Publish file'),
          content: TextField(
            controller: controller,
            autofocus: true,
            decoration: const InputDecoration(
              labelText: 'File path',
              hintText: '/path/to/file',
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(dialogContext).pop(),
              child: const Text('Cancel'),
            ),
            FilledButton(
              onPressed: () =>
                  Navigator.of(dialogContext).pop(controller.text.trim()),
              child: const Text('Publish'),
            ),
          ],
        );
      },
    );

    // Dispose the controller now that the dialog is dismissed.
    // Always dispose TextEditingControllers to free platform resources.
    controller.dispose();

    // Guard: user cancelled (null) or entered an empty path — do nothing.
    if (!mounted || path == null || path.isEmpty) return;

    // Show spinner during the backend call.
    setState(() => _publishing = true);

    final bridge = context.read<BackendBridge>();
    final ok = bridge.publishFile(path);

    // Reload so the newly published file appears in the list.
    await _load();

    if (mounted) {
      setState(() => _publishing = false);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            ok ? 'File published' : 'Failed to publish file',
          ),
        ),
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    // Show spinner during initial load or while a publish is in progress.
    // We block the whole screen during publish so the user does not tap
    // "Publish another file" a second time while the first is pending.
    if (_loading || _publishing) {
      return const Center(child: CircularProgressIndicator());
    }

    // Empty state — no published files yet.
    if (_files.isEmpty) {
      return EmptyState(
        icon: Icons.cloud_outlined,
        title: 'No published files',
        body: 'Publish a local file so this device can offer it over the mesh.',
        action: OutlinedButton.icon(
          onPressed: _promptPublishFile,
          icon: const Icon(Icons.publish_outlined),
          label: const Text('Publish a file'),
        ),
      );
    }

    // Non-empty: storage card + publish button + file tiles.
    return RefreshIndicator(
      // Pull-to-refresh re-fetches stats and file list.
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // Storage summary — shows used/total disk and published-file count.
          // Only rendered when _stats is non-null (i.e. after first load).
          if (_stats != null) _StorageCard(stats: _stats!),
          const SizedBox(height: 16),

          // "Publish another file" button — available even when files exist
          // so the user does not have to scroll to the top or use the AppBar.
          Align(
            alignment: Alignment.centerLeft,
            child: OutlinedButton.icon(
              onPressed: _promptPublishFile,
              icon: const Icon(Icons.publish_outlined),
              label: const Text('Publish another file'),
            ),
          ),
          const SizedBox(height: 12),

          // One tile per published file.
          // Each tile knows its own ID so it can pass it to _unpublish().
          for (final f in _files)
            _PublishedFileTile(
              file: f,
              // Extract the ID here rather than in _PublishedFileTile so the
              // tile stays stateless and ID-agnostic.
              onUnpublish: () => _unpublish(f['id'] as String? ?? ''),
            ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _StorageCard — disk-usage summary card
// ---------------------------------------------------------------------------

/// Displays a storage usage bar and published-file count.
///
/// When [stats] contains a non-zero totalBytes the widget renders a
/// [LinearProgressIndicator] showing the fraction of capacity used.
/// When totalBytes is zero (the backend does not yet know the device capacity)
/// the progress bar is omitted and a note is shown instead.
class _StorageCard extends StatelessWidget {
  const _StorageCard({required this.stats});

  /// Raw stats map from the backend.
  /// Expected keys: usedBytes (int), totalBytes (int), publishedFiles (int).
  final Map<String, dynamic> stats;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    // Parse with null-safe casts: the backend map uses dynamic values that
    // could theoretically be absent or wrong type on a stale backend version.
    final used      = (stats['usedBytes']      as num?)?.toInt() ?? 0;
    final total     = (stats['totalBytes']     as num?)?.toInt() ?? 0;
    final published = (stats['publishedFiles'] as num?)?.toInt() ?? 0;

    // hasCapacity controls whether we render the progress bar.
    // A zero total means the backend hasn't reported capacity yet.
    final hasCapacity = total > 0;

    // progress is the fill fraction for the bar (0.0–1.0).
    // When hasCapacity is false this value is unused.
    final progress = hasCapacity ? used / total : 0.0;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Storage', style: theme.textTheme.titleSmall),
            const SizedBox(height: 12),

            // Progress bar — only shown when we know the total capacity.
            if (hasCapacity) ...[
              ClipRRect(
                borderRadius: BorderRadius.circular(4),
                child: LinearProgressIndicator(
                  value: progress,
                  minHeight: 8,
                  backgroundColor: cs.surfaceContainerHighest,
                  // Use the brand colour for the filled portion so it is
                  // visually distinct from the system progress bar.
                  color: MeshTheme.brand,
                ),
              ),
              const SizedBox(height: 8),
            ],

            // Usage summary row: "X of Y used" on the left, file count on right.
            Row(children: [
              Text(
                // If capacity is unknown, just show the used amount with no fraction.
                hasCapacity
                    ? '${_formatBytes(used)} of ${_formatBytes(total)} used'
                    : _formatBytes(used),
                style: theme.textTheme.bodySmall,
              ),
              const Spacer(),
              Text(
                // "1 file published" vs "N files published" — pluralisation.
                '$published file${published == 1 ? '' : 's'} published',
                style: theme.textTheme.bodySmall
                    ?.copyWith(color: cs.onSurfaceVariant),
              ),
            ]),

            // Capacity note — only shown when total is zero (unknown).
            if (!hasCapacity) ...[
              const SizedBox(height: 8),
              Text(
                'Capacity reporting is not available yet on this device.',
                style: theme.textTheme.bodySmall
                    ?.copyWith(color: cs.onSurfaceVariant),
              ),
            ],
          ],
        ),
      ),
    );
  }

  /// Converts a raw byte count to a human-readable string (B, KB, MB, GB).
  ///
  /// Uses SI thresholds (1024-based) for consistency with the backend.
  /// Two decimal places for GB, one for KB/MB, zero for bytes.
  String _formatBytes(int bytes) {
    if (bytes < 1024) return '${bytes}B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)}KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)}MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)}GB';
  }
}

// ---------------------------------------------------------------------------
// _PublishedFileTile — one row per published file
// ---------------------------------------------------------------------------

/// Displays metadata for one published file and an Unpublish action button.
///
/// Intentionally stateless — all state lives in [_FilesSharedScreenState].
/// The tile receives an [onUnpublish] callback rather than calling the backend
/// directly, keeping it easy to test in isolation.
class _PublishedFileTile extends StatelessWidget {
  const _PublishedFileTile({required this.file, required this.onUnpublish});

  /// The raw file metadata map from the backend.
  /// Expected keys: name (String), sizeBytes (int), downloadCount (int).
  final Map<String, dynamic> file;

  /// Called when the user taps the Unpublish icon button.
  final VoidCallback onUnpublish;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    // Parse with null-safe casts so a missing or wrong-type field does not crash.
    final name      = file['name']          as String? ?? 'Unknown';
    final sizeBytes = (file['sizeBytes']    as num?)?.toInt() ?? 0;
    final downloads = (file['downloadCount'] as num?)?.toInt() ?? 0;

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        // Tinted file icon in the leading position.
        leading: Container(
          width: 40, height: 40,
          decoration: BoxDecoration(
            // 12% opacity tint of the brand colour as the icon background.
            color: MeshTheme.brand.withValues(alpha: 0.12),
            borderRadius: BorderRadius.circular(10),
          ),
          child: const Icon(Icons.insert_drive_file_outlined,
              size: 20, color: MeshTheme.brand),
        ),
        title: Text(name,
          style: theme.textTheme.titleSmall,
          maxLines: 1, overflow: TextOverflow.ellipsis),
        subtitle: Text(
          // "1.2MB · 3 downloads" — compact metadata line.
          // Pluralises "download" correctly.
          '${_formatBytes(sizeBytes)} · $downloads download${downloads == 1 ? '' : 's'}',
          style: theme.textTheme.bodySmall
              ?.copyWith(color: cs.onSurfaceVariant)),
        trailing: IconButton(
          // Red unpublish icon to signal a destructive action.
          icon: Icon(Icons.unpublished_outlined, color: cs.error),
          tooltip: 'Unpublish',
          onPressed: onUnpublish,
        ),
      ),
    );
  }

  /// Converts a raw byte count to a human-readable string (B, KB, MB).
  ///
  /// Only goes up to MB (not GB) because individual published files are
  /// unlikely to exceed a gigabyte in normal use; keeps the subtitle concise.
  String _formatBytes(int bytes) {
    if (bytes < 1024) return '${bytes}B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)}KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)}MB';
  }
}
