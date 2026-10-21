// transfers_screen.dart
//
// TransfersScreen is the first sub-page of the Files section.  It displays
// all known file transfers grouped into three sections:
//
//   1. Incoming Offers   — pending inbound transfers awaiting user action.
//   2. Active            — transfers currently in progress (upload or download).
//   3. Completed         — transfers that have reached a terminal state.
//
// INTERACTION PATTERNS
// --------------------
// • Pull-to-refresh calls FilesState.loadTransfers() to re-sync from Rust.
// • The upload FAB/AppBar icon opens SendFileSheet as a modal bottom sheet.
// • Each TransferTile shows inline Accept/Decline (for offers) or Cancel
//   (for active transfers) without navigating away.
//
// WHY THREE SECTIONS?
// -------------------
// Grouping by lifecycle state keeps the user's attention on what needs action
// (Incoming Offers at the top) and provides a clear history below.
// A flat chronological list would bury pending offers among completed ones.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../core/widgets/empty_state.dart';
import '../../../core/widgets/load_gate.dart';
// EmptyState — shared zero-data placeholder widget used when _transfers is empty.
import '../../../core/widgets/section_header.dart';
// SectionHeader — a styled "label" row that separates the three transfer groups.
import '../files_state.dart';
// FilesState — ChangeNotifier owning the transfer and service lists.
import '../widgets/transfer_tile.dart';
// TransferTile — renders one transfer row with progress bar and action buttons.
import 'send_file_sheet.dart';

// SendFileSheet — the "pick file + pick peer" bottom sheet.

/// The main list screen for the Files section.
///
/// This is a [StatelessWidget] because all mutable data lives in [FilesState].
/// The screen simply projects that data into widgets and delegates all
/// mutations back to [FilesState] methods.
class TransfersScreen extends StatelessWidget {
  const TransfersScreen({super.key});

  /// Opens [SendFileSheet] as a modal bottom sheet.
  ///
  /// [isScrollControlled: true] ensures the sheet resizes above the keyboard,
  /// which matters because the peer radio list can overflow on small screens.
  void _openSendSheet(BuildContext context) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (_) => const SendFileSheet(),
    );
  }

  @override
  Widget build(BuildContext context) {
    // context.watch subscribes this build to FilesState changes.
    // Any time FilesState.notifyListeners() fires (progress event, accept,
    // cancel, etc.) this build() is re-invoked with fresh data.
    final files = context.watch<FilesState>();

    return Scaffold(
      appBar: AppBar(
        title: const Text('Files'),
        actions: [
          // Upload icon in the AppBar provides a quick-access path to
          // SendFileSheet without needing to scroll to the FAB.
          IconButton(
            icon: const Icon(Icons.upload_file_outlined),
            tooltip: 'Send a file',
            onPressed: () => _openSendSheet(context),
          ),
          const SizedBox(width: 4),
        ],
      ),
      body: RefreshIndicator(
        // Pull-to-refresh re-fetches the full transfer list from Rust.
        // Useful if a background transfer completed while the app was
        // minimised and the EventBus missed the final state event.
        onRefresh: files.loadTransfers,
        // LoadGate (§22.50 / §22.51): 3 x 80 px shimmer while loading, the
        // ErrorBanner after a failed load, and the "No transfers" empty state
        // only after a successful load found nothing.
        child: LoadGate(
          loading: files.loading_transfers,
          error: files.transfers_error,
          is_empty: files.transfers.isEmpty,
          shimmer_count: 3,
          shimmer_height: 80,
          // Empty state — provides a direct call-to-action so the user knows
          // what to do.  Wrapped in a ListView so pull-to-refresh still works.
          empty: ListView(
            physics: const AlwaysScrollableScrollPhysics(),
            children: [
              EmptyState(
                icon: Icons.folder_open_outlined,
                title: 'No transfers',
                body: 'Tap the upload icon to send a file to a contact.',
                action: OutlinedButton.icon(
                  onPressed: () => _openSendSheet(context),
                  icon: const Icon(Icons.upload_file_outlined),
                  label: const Text('Send a file'),
                ),
              ),
            ],
          ),
          child: ListView(
            padding: const EdgeInsets.only(bottom: 16),
            children: [
              // ---- SECTION 1: Incoming Offers --------------------------------
              // Inbound transfers that the peer has proposed but we have not
              // yet accepted or declined.  Shown first because they require
              // user attention before the transfer can begin.
              if (files.incomingOffers.isNotEmpty) ...[
                const SectionHeader('Incoming Offers'),
                for (final t in files.incomingOffers)
                  TransferTile(
                    transfer: t,
                    // Accept: tell FilesState to call bridge.acceptFileTransfer()
                    // which moves the transfer from pending → active.
                    onAccept: () => files.acceptTransfer(t.id),
                    // Decline: reuses cancelTransfer — from the backend's
                    // perspective, declining an offer and cancelling an active
                    // transfer both call the same Rust method.
                    onDecline: () => files.cancelTransfer(t.id),
                  ),
              ],

              // ---- SECTION 2: Active -----------------------------------------
              // Transfers currently in flight.  The TransferTile shows a
              // LinearProgressIndicator and a cancel button for these.
              if (files.activeTransfers.isNotEmpty) ...[
                const SectionHeader('Active'),
                for (final t in files.activeTransfers)
                  TransferTile(
                    transfer: t,
                    onCancel: () => files.cancelTransfer(t.id),
                  ),
              ],

              // ---- SECTION 3: Completed --------------------------------------
              // Transfers in a terminal state (completed, failed, cancelled).
              // No action buttons — just a record of what happened.
              if (files.completedTransfers.isNotEmpty) ...[
                const SectionHeader('Completed'),
                for (final t in files.completedTransfers)
                  TransferTile(transfer: t),
              ],
            ],
          ),
        ),
      ),
    );
  }
}
