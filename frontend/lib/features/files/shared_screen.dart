import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../backend/backend_bridge.dart';
import '../../core/widgets/empty_state.dart';
import '../../app/app_theme.dart';

class FilesSharedScreen extends StatefulWidget {
  const FilesSharedScreen({super.key});
  @override
  State<FilesSharedScreen> createState() => _FilesSharedScreenState();
}

class _FilesSharedScreenState extends State<FilesSharedScreen> {
  Map<String, dynamic>? _stats;
  List<Map<String, dynamic>> _files = const [];
  bool _loading = true;
  bool _publishing = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

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

  Future<void> _unpublish(String fileId) async {
    final bridge = context.read<BackendBridge>();
    final ok = bridge.unpublishFile(fileId);
    if (ok) await _load();
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content: Text(ok ? 'File unpublished' : 'Failed to unpublish'),
      ));
    }
  }

  Future<void> _promptPublishFile() async {
    final controller = TextEditingController();
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
    controller.dispose();

    if (!mounted || path == null || path.isEmpty) return;

    setState(() => _publishing = true);
    final bridge = context.read<BackendBridge>();
    final ok = bridge.publishFile(path);
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

  @override
  Widget build(BuildContext context) {
    if (_loading || _publishing) {
      return const Center(child: CircularProgressIndicator());
    }

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

    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          if (_stats != null) _StorageCard(stats: _stats!),
          const SizedBox(height: 16),
          Align(
            alignment: Alignment.centerLeft,
            child: OutlinedButton.icon(
              onPressed: _promptPublishFile,
              icon: const Icon(Icons.publish_outlined),
              label: const Text('Publish another file'),
            ),
          ),
          const SizedBox(height: 12),
          for (final f in _files)
            _PublishedFileTile(
              file: f,
              onUnpublish: () => _unpublish(f['id'] as String? ?? ''),
            ),
        ],
      ),
    );
  }
}

class _StorageCard extends StatelessWidget {
  const _StorageCard({required this.stats});
  final Map<String, dynamic> stats;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;
    final used  = (stats['usedBytes']  as num?)?.toInt() ?? 0;
    final total = (stats['totalBytes'] as num?)?.toInt() ?? 0;
    final published = (stats['publishedFiles'] as num?)?.toInt() ?? 0;
    final hasCapacity = total > 0;
    final progress = hasCapacity ? used / total : 0.0;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Storage', style: theme.textTheme.titleSmall),
            const SizedBox(height: 12),
            if (hasCapacity) ...[
              ClipRRect(
                borderRadius: BorderRadius.circular(4),
                child: LinearProgressIndicator(
                  value: progress,
                  minHeight: 8,
                  backgroundColor: cs.surfaceContainerHighest,
                  color: MeshTheme.brand,
                ),
              ),
              const SizedBox(height: 8),
            ],
            Row(children: [
              Text(
                hasCapacity ? '${_formatBytes(used)} of ${_formatBytes(total)} used' : _formatBytes(used),
                style: theme.textTheme.bodySmall,
              ),
              const Spacer(),
              Text(
                '$published file${published == 1 ? '' : 's'} published',
                style: theme.textTheme.bodySmall
                    ?.copyWith(color: cs.onSurfaceVariant),
              ),
            ]),
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

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '${bytes}B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)}KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)}MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)}GB';
  }
}

class _PublishedFileTile extends StatelessWidget {
  const _PublishedFileTile({required this.file, required this.onUnpublish});
  final Map<String, dynamic> file;
  final VoidCallback onUnpublish;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;
    final name      = file['name']          as String? ?? 'Unknown';
    final sizeBytes = (file['sizeBytes'] as num?)?.toInt() ?? 0;
    final downloads = (file['downloadCount'] as num?)?.toInt() ?? 0;

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        leading: Container(
          width: 40, height: 40,
          decoration: BoxDecoration(
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
          '${_formatBytes(sizeBytes)} · $downloads download${downloads == 1 ? '' : 's'}',
          style: theme.textTheme.bodySmall
              ?.copyWith(color: cs.onSurfaceVariant)),
        trailing: IconButton(
          icon: Icon(Icons.unpublished_outlined, color: cs.error),
          tooltip: 'Unpublish',
          onPressed: onUnpublish,
        ),
      ),
    );
  }

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '${bytes}B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)}KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)}MB';
  }
}
