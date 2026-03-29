import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';

/// Backup & Restore screen.
///
/// **Export**: creates an encrypted backup of identity, trust data, network map,
/// and settings.  The backup blob is returned as a JSON string the user can
/// copy or share.
///
/// **Import**: restores from a previously-exported backup.  A new identity
/// keypair is generated on restore (spec section 3.7 — private keys are never
/// included in backups), so existing trusted peers will need to re-pair.
class BackupScreen extends StatefulWidget {
  const BackupScreen({super.key});

  @override
  State<BackupScreen> createState() => _BackupScreenState();
}

class _BackupScreenState extends State<BackupScreen> {
  // ---------------------------------------------------------------------------
  // Export state
  // ---------------------------------------------------------------------------
  final _exportPassCtl = TextEditingController();
  final _exportConfirmCtl = TextEditingController();
  bool _exportObscured = true;
  bool _exportBusy = false;
  String? _exportResult;
  String? _exportError;

  // ---------------------------------------------------------------------------
  // Import state
  // ---------------------------------------------------------------------------
  final _importDataCtl = TextEditingController();
  final _importPassCtl = TextEditingController();
  bool _importObscured = true;
  bool _importBusy = false;

  @override
  void dispose() {
    _exportPassCtl.dispose();
    _exportConfirmCtl.dispose();
    _importDataCtl.dispose();
    _importPassCtl.dispose();
    super.dispose();
  }

  // ---------------------------------------------------------------------------
  // Export logic
  // ---------------------------------------------------------------------------

  bool get _canExport =>
      !_exportBusy &&
      _exportPassCtl.text.length >= 12 &&
      _exportPassCtl.text == _exportConfirmCtl.text;

  Future<void> _onCreateBackup() async {
    setState(() {
      _exportBusy = true;
      _exportResult = null;
      _exportError = null;
    });

    final bridge = context.read<BackendBridge>();
    final result = bridge.createBackup(passphrase: _exportPassCtl.text);

    if (!mounted) return;

    if (result != null && result.isNotEmpty) {
      setState(() {
        _exportBusy = false;
        _exportResult = result;
      });
    } else {
      final err = bridge.getLastError() ?? 'Unknown error';
      setState(() {
        _exportBusy = false;
        _exportError = err;
      });
    }
  }

  // ---------------------------------------------------------------------------
  // Import logic
  // ---------------------------------------------------------------------------

  bool get _canImport =>
      !_importBusy &&
      _importDataCtl.text.trim().isNotEmpty &&
      _importPassCtl.text.isNotEmpty;

  Future<void> _onRestoreBackup() async {
    // Confirmation dialog first.
    final confirmed = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => AlertDialog(
        title: const Text('Restore Backup'),
        content: const Text(
          'Restoring will merge backup data (contacts, rooms, messages) '
          'into your current identity. Your identity keypair is preserved.\n\n'
          'Are you sure you want to continue?',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Restore'),
          ),
        ],
      ),
    );

    if (confirmed != true || !mounted) return;

    setState(() => _importBusy = true);

    final bridge = context.read<BackendBridge>();
    final ok = bridge.importIdentity(
      backupJson: _importDataCtl.text.trim(),
      passphrase: _importPassCtl.text,
    );

    if (!mounted) return;

    if (ok) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Backup restored successfully')),
      );
      // Pop back to root so the app reloads with the restored identity.
      Navigator.of(context).popUntil((route) => route.isFirst);
    } else {
      setState(() => _importBusy = false);
      final err = bridge.getLastError() ?? 'Invalid passphrase or corrupted backup';
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Restore failed: $err')),
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    return Scaffold(
      appBar: AppBar(title: const Text('Backup & Restore')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // =================================================================
          // EXPORT SECTION
          // =================================================================
          const _SectionHeader('Export Backup', icon: Icons.upload_outlined),

          const SizedBox(height: 8),

          // Warning banner
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: cs.secondaryContainer,
              borderRadius: BorderRadius.circular(12),
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(Icons.info_outline, color: cs.onSecondaryContainer, size: 20),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    'This backup contains your network map and profile data. '
                    'Store it securely. Private keys are never included.',
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          color: cs.onSecondaryContainer,
                        ),
                  ),
                ),
              ],
            ),
          ),

          const SizedBox(height: 16),

          // Passphrase field
          TextField(
            controller: _exportPassCtl,
            obscureText: _exportObscured,
            onChanged: (_) => setState(() {}),
            decoration: InputDecoration(
              labelText: 'Passphrase (min. 12 characters)',
              border: const OutlineInputBorder(),
              suffixIcon: IconButton(
                icon: Icon(
                  _exportObscured ? Icons.visibility_outlined : Icons.visibility_off_outlined,
                ),
                onPressed: () => setState(() => _exportObscured = !_exportObscured),
              ),
            ),
          ),

          const SizedBox(height: 12),

          // Confirm passphrase
          TextField(
            controller: _exportConfirmCtl,
            obscureText: _exportObscured,
            onChanged: (_) => setState(() {}),
            decoration: const InputDecoration(
              labelText: 'Confirm passphrase',
              border: OutlineInputBorder(),
            ),
          ),

          const SizedBox(height: 16),

          // Create Backup button
          FilledButton.icon(
            onPressed: _canExport ? _onCreateBackup : null,
            icon: _exportBusy
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.lock_outlined),
            label: Text(_exportBusy ? 'Creating backup...' : 'Create Backup'),
            style: FilledButton.styleFrom(minimumSize: const Size.fromHeight(48)),
          ),

          // Export error
          if (_exportError != null) ...[
            const SizedBox(height: 12),
            Text(
              _exportError!,
              style: TextStyle(color: cs.error),
            ),
          ],

          // Export result
          if (_exportResult != null) ...[
            const SizedBox(height: 16),
            Text(
              'Backup created successfully',
              style: Theme.of(context).textTheme.titleSmall?.copyWith(
                    color: cs.primary,
                    fontWeight: FontWeight.w600,
                  ),
            ),
            const SizedBox(height: 8),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: cs.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(8),
              ),
              constraints: const BoxConstraints(maxHeight: 200),
              child: SingleChildScrollView(
                child: SelectableText(
                  _exportResult!,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
                ),
              ),
            ),
            const SizedBox(height: 8),
            OutlinedButton.icon(
              onPressed: () {
                Clipboard.setData(ClipboardData(text: _exportResult!));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Backup copied to clipboard')),
                );
              },
              icon: const Icon(Icons.copy_outlined),
              label: const Text('Copy to Clipboard'),
              style: OutlinedButton.styleFrom(minimumSize: const Size.fromHeight(44)),
            ),
          ],

          const SizedBox(height: 32),
          const Divider(),
          const SizedBox(height: 16),

          // =================================================================
          // IMPORT SECTION
          // =================================================================
          const _SectionHeader('Restore Backup', icon: Icons.download_outlined),

          const SizedBox(height: 8),

          // Warning banner
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: cs.errorContainer,
              borderRadius: BorderRadius.circular(12),
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(Icons.warning_amber_rounded,
                    color: cs.onErrorContainer, size: 20),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    'Restoring merges backup data into your current identity. '
                    'Your keypair and peer ID are preserved.',
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          color: cs.onErrorContainer,
                          fontWeight: FontWeight.w600,
                        ),
                  ),
                ),
              ],
            ),
          ),

          const SizedBox(height: 16),

          // Backup data field
          TextField(
            controller: _importDataCtl,
            maxLines: 5,
            onChanged: (_) => setState(() {}),
            decoration: const InputDecoration(
              labelText: 'Paste backup data',
              alignLabelWithHint: true,
              border: OutlineInputBorder(),
              hintText: '{"version":1,"salt":...}',
            ),
          ),

          const SizedBox(height: 12),

          // Passphrase field
          TextField(
            controller: _importPassCtl,
            obscureText: _importObscured,
            onChanged: (_) => setState(() {}),
            decoration: InputDecoration(
              labelText: 'Passphrase',
              border: const OutlineInputBorder(),
              suffixIcon: IconButton(
                icon: Icon(
                  _importObscured ? Icons.visibility_outlined : Icons.visibility_off_outlined,
                ),
                onPressed: () => setState(() => _importObscured = !_importObscured),
              ),
            ),
          ),

          const SizedBox(height: 16),

          // Restore button
          FilledButton.icon(
            onPressed: _canImport ? _onRestoreBackup : null,
            icon: _importBusy
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.restore_outlined),
            label: Text(_importBusy ? 'Restoring...' : 'Restore Backup'),
            style: FilledButton.styleFrom(minimumSize: const Size.fromHeight(48)),
          ),

          const SizedBox(height: 32),
        ],
      ),
    );
  }
}

class _SectionHeader extends StatelessWidget {
  const _SectionHeader(this.title, {required this.icon});

  final String title;
  final IconData icon;

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Icon(icon, size: 20, color: Theme.of(context).colorScheme.primary),
        const SizedBox(width: 8),
        Text(
          title,
          style: Theme.of(context).textTheme.titleMedium?.copyWith(
                color: Theme.of(context).colorScheme.primary,
                fontWeight: FontWeight.bold,
              ),
        ),
      ],
    );
  }
}
