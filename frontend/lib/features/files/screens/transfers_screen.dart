import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../files_state.dart';
import '../widgets/transfer_tile.dart';

class TransfersScreen extends StatelessWidget {
  const TransfersScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final files = context.watch<FilesState>();

    return Scaffold(
      appBar: AppBar(title: const Text('File Transfers')),
      body: RefreshIndicator(
        onRefresh: files.loadTransfers,
        child: files.transfers.isEmpty
            ? _EmptyState()
            : ListView(
                padding: const EdgeInsets.symmetric(vertical: 8),
                children: [
                  if (files.activeTransfers.isNotEmpty) ...[
                    const _SectionHeader('Active'),
                    for (final t in files.activeTransfers)
                      TransferTile(
                        transfer: t,
                        onCancel: () => files.cancelTransfer(t.id),
                      ),
                  ],
                  if (files.completedTransfers.isNotEmpty) ...[
                    const _SectionHeader('Completed'),
                    for (final t in files.completedTransfers)
                      TransferTile(transfer: t),
                  ],
                ],
              ),
      ),
    );
  }
}

class _SectionHeader extends StatelessWidget {
  const _SectionHeader(this.title);

  final String title;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(20, 16, 20, 4),
      child: Text(
        title,
        style: Theme.of(context).textTheme.labelMedium?.copyWith(
          color: Theme.of(context).colorScheme.onSurfaceVariant,
        ),
      ),
    );
  }
}

class _EmptyState extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            Icons.folder_open_outlined,
            size: 64,
            color: Theme.of(context).colorScheme.outline,
          ),
          const SizedBox(height: 16),
          Text('No transfers', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 8),
          Text(
            'Send a file from a conversation to get started',
            style: Theme.of(context).textTheme.bodySmall?.copyWith(
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ),
    );
  }
}
