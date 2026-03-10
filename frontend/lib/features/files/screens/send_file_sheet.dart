import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/models/peer_models.dart';
import '../../peers/peers_state.dart';
import '../files_state.dart';

class SendFileSheet extends StatefulWidget {
  const SendFileSheet({super.key});

  @override
  State<SendFileSheet> createState() => _SendFileSheetState();
}

class _SendFileSheetState extends State<SendFileSheet> {
  PeerModel? _selectedPeer;
  String? _filePath;
  String? _fileName;
  bool _sending = false;

  Future<void> _pickFile() async {
    final result = await FilePicker.platform.pickFiles();
    if (result != null && result.files.single.path != null) {
      setState(() {
        _filePath = result.files.single.path;
        _fileName = result.files.single.name;
      });
    }
  }

  Future<void> _send() async {
    if (_selectedPeer == null || _filePath == null) return;
    setState(() => _sending = true);
    final ok = await context.read<FilesState>().sendFile(
      peerId: _selectedPeer!.id,
      filePath: _filePath!,
    );
    if (!mounted) return;
    setState(() => _sending = false);
    if (ok) {
      Navigator.pop(context);
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Failed to start transfer')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final peers = context.watch<PeersState>().peers;
    final canSend = _selectedPeer != null && _filePath != null && !_sending;

    return Padding(
      padding: EdgeInsets.fromLTRB(
        16,
        16,
        16,
        MediaQuery.viewInsetsOf(context).bottom + 24,
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
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
          OutlinedButton.icon(
            icon: const Icon(Icons.attach_file),
            label: Text(_fileName ?? 'Choose File'),
            onPressed: _pickFile,
          ),
          const SizedBox(height: 16),
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
            RadioGroup<PeerModel>(
              groupValue: _selectedPeer,
              onChanged: (v) => setState(() => _selectedPeer = v),
              child: Column(
                children: [
                  for (final peer in peers)
                    RadioListTile<PeerModel>(
                      title: Text(peer.name),
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
