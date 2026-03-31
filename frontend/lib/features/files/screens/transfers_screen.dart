import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../core/widgets/empty_state.dart';
import '../../../core/widgets/section_header.dart';
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
      appBar: AppBar(
        title: const Text('Files'),
        actions: [
          IconButton(
            icon: const Icon(Icons.upload_file_outlined),
            tooltip: 'Send a file',
            onPressed: () => _openSendSheet(context),
          ),
          const SizedBox(width: 4),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: files.loadTransfers,
        child: ListView(
          padding: const EdgeInsets.only(bottom: 16),
          children: [
            if (files.transfers.isEmpty)
              EmptyState(
                icon: Icons.folder_open_outlined,
                title: 'No transfers',
                body: 'Tap the upload icon to send a file to a contact.',
                action: OutlinedButton.icon(
                  onPressed: () => _openSendSheet(context),
                  icon: const Icon(Icons.upload_file_outlined),
                  label: const Text('Send a file'),
                ),
              )
            else ...[
              if (files.incomingOffers.isNotEmpty) ...[
                const SectionHeader('Incoming Offers'),
                for (final t in files.incomingOffers)
                  TransferTile(
                    transfer: t,
                    onAccept: () => files.acceptTransfer(t.id),
                    onDecline: () => files.cancelTransfer(t.id),
                  ),
              ],
              if (files.activeTransfers.isNotEmpty) ...[
                const SectionHeader('Active'),
                for (final t in files.activeTransfers)
                  TransferTile(
                    transfer: t,
                    onCancel: () => files.cancelTransfer(t.id),
                  ),
              ],
              if (files.completedTransfers.isNotEmpty) ...[
                const SectionHeader('Completed'),
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
