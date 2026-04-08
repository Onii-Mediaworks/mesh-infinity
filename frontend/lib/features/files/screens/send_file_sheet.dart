// send_file_sheet.dart
//
// SendFileSheet is the bottom sheet that the user sees when they tap the
// "Send File" button in TransfersScreen.
//
// FLOW
// ----
//   1. User taps "Choose File" → FilePicker opens the OS file picker.
//   2. User selects a peer from the radio group (only paired peers shown).
//   3. User taps "Send" → FilesState.sendFile() is called.
//   4. On success: sheet closes and the transfer appears in TransfersScreen.
//      On failure: a SnackBar explains the problem.
//
// WHY IS THIS A BOTTOM SHEET INSTEAD OF A FULL SCREEN?
// -------------------------------------------------------
// Sending a file is a lightweight, quick action — pick file, pick peer, go.
// A modal bottom sheet fits the "quick action" UX pattern better than
// pushing a full route, and it keeps the user on the transfers screen so
// they immediately see the new entry when the sheet closes.

import 'package:file_picker/file_picker.dart';
// FilePicker.platform.pickFiles() opens the platform's native file chooser
// (UIDocumentPicker on iOS, SAF on Android, GTK on Linux, etc.).
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/models/peer_models.dart';
// PeerModel — typed peer data: id, name, isOnline, trustLevel.
import '../../peers/peers_state.dart';
// PeersState — ChangeNotifier that owns the list of known paired peers.
import '../files_state.dart';
// FilesState — owns the transfer list and exposes sendFile().

/// A modal bottom sheet for sending a file to a paired peer.
///
/// Use via [showModalBottomSheet]:
/// ```dart
/// showModalBottomSheet(
///   context: context,
///   isScrollControlled: true,  // required so the sheet resizes above keyboard
///   builder: (_) => const SendFileSheet(),
/// );
/// ```
///
/// [isScrollControlled] is required because the sheet contains an OS-provided
/// keyboard (when no file is picked, focus shifts to the peer list).  Without
/// it the bottom of the sheet is hidden behind the keyboard.
class SendFileSheet extends StatefulWidget {
  const SendFileSheet({super.key});

  @override
  State<SendFileSheet> createState() => _SendFileSheetState();
}

class _SendFileSheetState extends State<SendFileSheet> {
  // ---------------------------------------------------------------------------
  // State fields
  // ---------------------------------------------------------------------------

  /// The peer the user has selected to receive the file.
  /// Null until the user taps a radio tile.  The Send button is disabled
  /// while this is null so we never call sendFile() without a destination.
  PeerModel? _selectedPeer;

  /// Absolute filesystem path of the picked file, as returned by FilePicker.
  /// Null until the user picks a file.
  String? _filePath;

  /// Human-readable filename shown on the "Choose File" button after picking.
  /// Null before picking.
  String? _fileName;

  /// True while the backend sendFile() call is in flight.
  /// Disables the Send button and swaps the icon for a spinner to prevent
  /// double-submission.
  bool _sending = false;

  // ---------------------------------------------------------------------------
  // Actions
  // ---------------------------------------------------------------------------

  /// Opens the OS file picker and stores the selected file path.
  ///
  /// [FilePicker.platform.pickFiles()] is async — it suspends until the user
  /// makes a selection or cancels.  We only update state if a file was actually
  /// chosen (result != null) and the path is non-null.
  ///
  /// WHY check result.files.single.path for null?
  /// On some platforms (iOS in particular) a picked file may not have a direct
  /// filesystem path — it exists only as a read stream.  The backend expects a
  /// path string, so we guard against the null case here.
  Future<void> _pickFile() async {
    final result = await FilePicker.platform.pickFiles();
    if (result != null && result.files.single.path != null) {
      setState(() {
        _filePath = result.files.single.path;
        _fileName = result.files.single.name;
      });
    }
  }

  /// Initiates the file transfer and closes the sheet on success.
  ///
  /// Guards against double-sends: the Send button is disabled while _sending
  /// is true (canSend is false), but we also check _selectedPeer and _filePath
  /// as a belt-and-suspenders guard.
  ///
  /// After the async sendFile() call we check [mounted] before touching any
  /// widget state — if the user closed the sheet while the call was in flight
  /// (unlikely but possible) we must not call setState on a dead widget.
  Future<void> _send() async {
    // Belt-and-suspenders null check — the button should already be disabled
    // if either is null, but guard anyway to prevent a null-dereference.
    if (_selectedPeer == null || _filePath == null) return;

    setState(() => _sending = true);

    final ok = await context.read<FilesState>().sendFile(
      peerId: _selectedPeer!.id,
      filePath: _filePath!,
    );

    // Guard: the user could navigate away (e.g. back button) while the async
    // call was in flight.  mounted is false in that case, so stop here.
    if (!mounted) return;

    setState(() => _sending = false);

    if (ok) {
      // Close the sheet — the new transfer is already visible in the list
      // because sendFile() called loadTransfers() → notifyListeners().
      Navigator.pop(context);
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Failed to start transfer')),
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    // context.watch subscribes this build to PeersState changes so the peer
    // list stays up to date if peers connect/disconnect while the sheet is open.
    final peers = context.watch<PeersState>().peers;

    // All three conditions must be true before we allow the send action:
    //   1. A peer has been selected.
    //   2. A file has been picked.
    //   3. No send is already in flight (prevents double-send).
    final canSend = _selectedPeer != null && _filePath != null && !_sending;

    return Padding(
      padding: EdgeInsets.fromLTRB(
        16,
        16,
        16,
        // Add the keyboard's height to the bottom padding so the sheet
        // content is never hidden behind the software keyboard.
        MediaQuery.viewInsetsOf(context).bottom + 24,
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Header row: title + close button.
          Row(
            children: [
              Text('Send File', style: Theme.of(context).textTheme.titleMedium),
              const Spacer(),
              IconButton(
                icon: const Icon(Icons.close),
                onPressed: () => Navigator.pop(context),
                visualDensity: VisualDensity.compact,
              ),
            ],
          ),
          const SizedBox(height: 16),

          // File-picker button — label updates to the filename after picking.
          OutlinedButton.icon(
            icon: const Icon(Icons.attach_file),
            label: Text(_fileName ?? 'Choose File'),
            onPressed: _pickFile,
          ),
          const SizedBox(height: 16),

          // Peer selection — show a helpful hint if there are no paired peers,
          // otherwise show a radio group so only one peer can be selected at a time.
          if (peers.isEmpty)
            Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: Text(
                'No paired peers. Add peers in the Peers tab first.',
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
              ),
            )
          else ...[
            Text(
              'Send to',
              style: Theme.of(context).textTheme.labelMedium?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 4),

            // RadioGroup enforces that only one peer can be selected at a time.
            // Selecting a different peer updates _selectedPeer via setState.
            RadioGroup<PeerModel>(
              groupValue: _selectedPeer,
              onChanged: (v) => setState(() => _selectedPeer = v),
              child: Column(
                children: [
                  for (final peer in peers)
                    RadioListTile<PeerModel>(
                      title: Text(peer.name),
                      // Show online status in green so the user knows which
                      // peers can actually receive a transfer right now.
                      subtitle: Text(
                        peer.isOnline ? 'Online' : 'Offline',
                        style: TextStyle(
                          color: peer.isOnline
                              ? Colors.green
                              : Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                      ),
                      value: peer,
                      contentPadding: EdgeInsets.zero,
                      dense: true,
                    ),
                ],
              ),
            ),
            const SizedBox(height: 8),
          ],

          // Send button — disabled (null onPressed) until both peer and file
          // are selected, and while a send is in flight.
          // The icon swaps to a spinner while _sending is true so the user
          // gets clear feedback that the action is processing.
          FilledButton.icon(
            icon: _sending
                ? const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(
                      strokeWidth: 2,
                      color: Colors.white,
                    ),
                  )
                : const Icon(Icons.send),
            label: const Text('Send'),
            onPressed: canSend ? _send : null,
          ),
        ],
      ),
    );
  }
}
