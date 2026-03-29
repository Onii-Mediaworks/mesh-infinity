import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/models/settings_models.dart';
import '../files_state.dart';
import '../widgets/transfer_tile.dart';
import 'send_file_sheet.dart';

class TransfersScreen extends StatelessWidget {
  const TransfersScreen({super.key});

  void _openSendSheet(BuildContext context) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (_) => const SendFileSheet(),
    );
  }

  @override
  Widget build(BuildContext context) {
    final files = context.watch<FilesState>();

    return Scaffold(
      appBar: AppBar(title: const Text('Files')),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () => _openSendSheet(context),
        icon: const Icon(Icons.upload_file_outlined),
        label: const Text('Send File'),
      ),
      body: RefreshIndicator(
        onRefresh: files.loadTransfers,
        child: ListView(
          padding: const EdgeInsets.only(bottom: 88),
          children: [
            const _SectionHeader('File Sharing Services'),
            if (files.services.isEmpty)
              const Padding(
                padding: EdgeInsets.fromLTRB(20, 4, 20, 12),
                child: Text('No file hosting services configured'),
              )
            else
              for (final svc in files.services)
                _ServiceTile(
                  service: svc,
                  onToggle: (enabled) =>
                      files.configureService(svc.id, {'enabled': enabled}),
                ),
            const Divider(height: 24),
            if (files.transfers.isEmpty)
              _EmptyTransfers()
            else ...[
              if (files.incomingOffers.isNotEmpty) ...[
                const _SectionHeader('Incoming Offers'),
                for (final t in files.incomingOffers)
                  TransferTile(
                    transfer: t,
                    onAccept:  () => files.acceptTransfer(t.id),
                    onDecline: () => files.cancelTransfer(t.id),
                  ),
              ],
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

class _ServiceTile extends StatelessWidget {
  const _ServiceTile({required this.service, required this.onToggle});

  final ServiceModel service;
  final ValueChanged<bool> onToggle;

  @override
  Widget build(BuildContext context) {
    return SwitchListTile(
      secondary: const Icon(Icons.folder_shared_outlined),
      title: Text(service.name),
      subtitle: service.address.isNotEmpty ? Text(service.address) : null,
      value: service.enabled,
      onChanged: onToggle,
      contentPadding: const EdgeInsets.symmetric(horizontal: 20, vertical: 2),
    );
  }
}

class _EmptyTransfers extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 40),
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
            'Tap Send File to share with a contact',
            style: Theme.of(context).textTheme.bodySmall?.copyWith(
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ),
    );
  }
}
