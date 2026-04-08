// transfer_tile.dart
//
// TransferTile renders a single file-transfer entry in the TransfersScreen
// list.  Its appearance changes depending on the transfer's lifecycle state:
//
//   PENDING (inbound offer)
//     - File name + "Pending" status chip.
//     - File size in subtitle.
//     - Accept (green tick) + Decline (red X) icon buttons in the trailing area.
//
//   ACTIVE (in flight)
//     - File name + "Active" status chip.
//     - LinearProgressIndicator with byte-transferred and percentage labels.
//     - Cancel (X) icon button.
//
//   TERMINAL (completed, failed, cancelled)
//     - File name + coloured status chip (green = done, red = failed, etc.).
//     - File size in subtitle.
//     - No action buttons.
//
// WHY DOES ONE TILE HANDLE ALL STATES?
// --------------------------------------
// All three states display the same core information (file name, size,
// direction) and differ only in which extra widgets appear.  A single widget
// with conditional children is simpler than three separate tile classes that
// would share almost all their code.

import 'package:flutter/material.dart';

import '../../../backend/models/file_transfer_models.dart';
// FileTransferModel — typed model with: id, name, direction, status,
//   progress (0.0–1.0), transferredBytes, sizeBytes.
// TransferStatus — enum with values: pending, active, paused, completed, failed.
// TransferDirection — enum with values: send, receive.

/// A card widget that displays one [FileTransferModel] and provides inline
/// Accept/Decline (pending) or Cancel (active) action callbacks.
///
/// All callbacks are nullable so the tile can be used in read-only mode
/// (e.g. completed transfers) without conditional logic at the call site.
class TransferTile extends StatelessWidget {
  const TransferTile({
    super.key,
    required this.transfer,
    this.onCancel,
    this.onAccept,
    this.onDecline,
  });

  /// The transfer data to display.
  final FileTransferModel transfer;

  /// Called when the user taps the Cancel button on an active transfer.
  /// Null for pending/completed transfers (button is not shown).
  final VoidCallback? onCancel;

  /// Called when the user taps the Accept button on an inbound pending offer.
  /// Null for outgoing / active / terminal transfers.
  final VoidCallback? onAccept;

  /// Called when the user taps the Decline button on an inbound pending offer.
  /// Null for outgoing / active / terminal transfers.
  final VoidCallback? onDecline;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    // True if we are sending this file (outgoing).
    // Used to pick the correct direction arrow icon in the header row.
    final isSend = transfer.direction == TransferDirection.send;

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // ---- Header row ------------------------------------------------
            // Contains: direction icon | file name | status chip | action buttons
            Row(
              children: [
                // Upload arrow for sends, download arrow for receives.
                Icon(
                  isSend ? Icons.upload_outlined : Icons.download_outlined,
                  size: 18,
                  color: cs.primary,
                ),
                const SizedBox(width: 8),

                // File name — truncated with ellipsis to keep layout stable
                // when names are very long.
                Expanded(
                  child: Text(
                    transfer.name,
                    style: Theme.of(context).textTheme.titleSmall,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),

                // Status chip — colour-coded pill indicating lifecycle state.
                _StatusChip(status: transfer.status),

                // Action buttons — only shown for the relevant states.
                if (transfer.status == TransferStatus.pending &&
                    transfer.direction == TransferDirection.receive) ...[
                  // Inbound pending offer: Accept + Decline buttons.
                  // Only receive-direction transfers need these — we don't
                  // wait for the remote peer's acceptance to appear here.
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
                  // Active transfer with a cancel handler provided: show X.
                  // We only show Cancel if onCancel is non-null so the tile
                  // can be used in view-only contexts.
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

            // ---- Progress / size area --------------------------------------
            // Active transfers show a progress bar + byte counters.
            // All other states show just the file size.
            if (transfer.status.isActive) ...[
              const SizedBox(height: 10),

              // LinearProgressIndicator: value ∈ [0.0, 1.0] where
              // 0 = just started, 1 = fully transferred.
              LinearProgressIndicator(
                value: transfer.progress,
                borderRadius: BorderRadius.circular(4),
              ),
              const SizedBox(height: 6),

              // Byte counter row: "transferred / total" on the left, "XX%" on right.
              Row(
                children: [
                  // Bold transferred amount draws the eye to how far along we are.
                  Text(
                    _formatBytes(transfer.transferredBytes),
                    style: Theme.of(context).textTheme.labelSmall,
                  ),
                  // Muted total amount provides context without competing with
                  // the transferred amount.
                  Text(
                    ' / ${_formatBytes(transfer.sizeBytes)}',
                    style: Theme.of(context).textTheme.labelSmall?.copyWith(
                      color: cs.onSurfaceVariant,
                    ),
                  ),
                  const Spacer(),
                  // Percentage — toStringAsFixed(0) rounds to the nearest
                  // integer, keeping the label clean (e.g. "47%" not "47.3%").
                  Text(
                    '${(transfer.progress * 100).toStringAsFixed(0)}%',
                    style: Theme.of(context).textTheme.labelSmall,
                  ),
                ],
              ),
            ] else ...[
              const SizedBox(height: 4),
              // For non-active states (pending, completed, failed) just show
              // the total file size as a secondary label.
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

  /// Converts a raw byte count to a human-readable string.
  ///
  /// Uses 1024-based thresholds (IEC binary prefixes).
  /// B → KB (1 decimal) → MB (1 decimal) → GB (2 decimal).
  String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }
}

// ---------------------------------------------------------------------------
// _StatusChip — colour-coded status pill
// ---------------------------------------------------------------------------

/// A small pill-shaped badge showing the transfer's current status.
///
/// The colour encoding matches the expected semantics:
///   - Pending → grey   (waiting, no action taken)
///   - Active  → blue   (in progress)
///   - Paused  → orange (halted, can resume)
///   - Completed → green (success)
///   - Failed  → red    (error)
///
/// Background opacity is 12% of the status colour so the chip is
/// readable in both light and dark themes without being visually dominant.
class _StatusChip extends StatelessWidget {
  const _StatusChip({required this.status});

  /// The status to visualise.
  final TransferStatus status;

  @override
  Widget build(BuildContext context) {
    // Dart 3 record destructuring — the switch evaluates to a (String, Color)
    // record that we immediately destructure into label + color.
    final (label, color) = switch (status) {
      TransferStatus.pending   => ('Pending',  Colors.grey),
      TransferStatus.active    => ('Active',   Colors.blue),
      TransferStatus.paused    => ('Paused',   Colors.orange),
      TransferStatus.completed => ('Done',     Colors.green),
      TransferStatus.failed    => ('Failed',   Colors.red),
    };

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(
        // 12% opacity fill — just enough to distinguish the chip from the
        // card background without overwhelming the name text beside it.
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(10),
        // 40% opacity border gives the chip a defined edge in dark mode.
        border: Border.all(color: color.withValues(alpha: 0.4)),
      ),
      child: Text(
        label,
        style: TextStyle(fontSize: 11, color: color, fontWeight: FontWeight.w600),
      ),
    );
  }
}
