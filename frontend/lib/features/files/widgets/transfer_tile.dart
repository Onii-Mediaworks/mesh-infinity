import 'package:flutter/material.dart';

import '../../../backend/models/file_transfer_models.dart';

class TransferTile extends StatelessWidget {
  const TransferTile({
    super.key,
    required this.transfer,
    this.onCancel,
    this.onAccept,
    this.onDecline,
  });

  final FileTransferModel transfer;
  final VoidCallback? onCancel;
  final VoidCallback? onAccept;
  final VoidCallback? onDecline;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final isSend = transfer.direction == TransferDirection.send;

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  isSend ? Icons.upload_outlined : Icons.download_outlined,
                  size: 18,
                  color: cs.primary,
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    transfer.name,
                    style: Theme.of(context).textTheme.titleSmall,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                _StatusChip(status: transfer.status),
                if (transfer.status == TransferStatus.pending &&
                    transfer.direction == TransferDirection.receive) ...[
                  const SizedBox(width: 4),
                  IconButton(
                    icon: const Icon(Icons.check_circle_outline, size: 18),
                    tooltip: 'Accept',
                    color: Colors.green,
                    onPressed: onAccept,
                    visualDensity: VisualDensity.compact,
                  ),
                  IconButton(
                    icon: const Icon(Icons.cancel_outlined, size: 18),
                    tooltip: 'Decline',
                    color: Colors.red,
                    onPressed: onDecline,
                    visualDensity: VisualDensity.compact,
                  ),
                ] else if (transfer.status.isActive && onCancel != null) ...[
                  const SizedBox(width: 8),
                  IconButton(
                    icon: const Icon(Icons.close, size: 18),
                    tooltip: 'Cancel',
                    onPressed: onCancel,
                    visualDensity: VisualDensity.compact,
                  ),
                ],
              ],
            ),
            if (transfer.status.isActive) ...[
              const SizedBox(height: 10),
              LinearProgressIndicator(
                value: transfer.progress,
                borderRadius: BorderRadius.circular(4),
              ),
              const SizedBox(height: 6),
              Row(
                children: [
                  Text(
                    _formatBytes(transfer.transferredBytes),
                    style: Theme.of(context).textTheme.labelSmall,
                  ),
                  Text(
                    ' / ${_formatBytes(transfer.sizeBytes)}',
                    style: Theme.of(context).textTheme.labelSmall?.copyWith(
                      color: cs.onSurfaceVariant,
                    ),
                  ),
                  const Spacer(),
                  Text(
                    '${(transfer.progress * 100).toStringAsFixed(0)}%',
                    style: Theme.of(context).textTheme.labelSmall,
                  ),
                ],
              ),
            ] else ...[
              const SizedBox(height: 4),
              Text(
                _formatBytes(transfer.sizeBytes),
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: cs.onSurfaceVariant,
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }
}

class _StatusChip extends StatelessWidget {
  const _StatusChip({required this.status});

  final TransferStatus status;

  @override
  Widget build(BuildContext context) {
    final (label, color) = switch (status) {
      TransferStatus.pending => ('Pending', Colors.grey),
      TransferStatus.active => ('Active', Colors.blue),
      TransferStatus.paused => ('Paused', Colors.orange),
      TransferStatus.completed => ('Done', Colors.green),
      TransferStatus.failed => ('Failed', Colors.red),
    };

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withValues(alpha: 0.4)),
      ),
      child: Text(
        label,
        style: TextStyle(fontSize: 11, color: color, fontWeight: FontWeight.w600),
      ),
    );
  }
}
