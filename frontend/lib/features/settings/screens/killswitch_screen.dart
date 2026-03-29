import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';

/// Emergency data destruction screen (§3.9).
///
/// Calls [BackendBridge.emergencyErase] which performs a standard killswitch
/// erase: overwrites identity.key with random bytes (permanently orphaning
/// identity.dat), then deletes all vault files. After destruction the app
/// navigates back to root so the onboarding flow restarts.
class KillswitchScreen extends StatefulWidget {
  const KillswitchScreen({super.key});

  @override
  State<KillswitchScreen> createState() => _KillswitchScreenState();
}

class _KillswitchScreenState extends State<KillswitchScreen> {
  bool _acknowledged = false;
  bool _busy = false;

  Future<void> _onDestroy() async {
    // Second confirmation: require the user to type DELETE.
    final confirmed = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => _ConfirmDeleteDialog(),
    );

    if (confirmed != true || !mounted) return;

    setState(() => _busy = true);

    final bridge = context.read<BackendBridge>();
    final ok = bridge.emergencyErase();

    if (!mounted) return;

    if (ok) {
      // Navigate to root and clear the stack so onboarding shows.
      Navigator.of(context).popUntil((route) => route.isFirst);
    } else {
      setState(() => _busy = false);
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Failed to destroy data')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Emergency Data Destruction'),
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // Warning banner
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: cs.errorContainer,
              borderRadius: BorderRadius.circular(12),
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(Icons.warning_amber_rounded,
                    color: cs.onErrorContainer, size: 28),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    'This action is IRREVERSIBLE. All data on this device will '
                    'be permanently destroyed and cannot be recovered.',
                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                          color: cs.onErrorContainer,
                          fontWeight: FontWeight.w600,
                        ),
                  ),
                ),
              ],
            ),
          ),

          const SizedBox(height: 24),

          Text(
            'The following will be permanently destroyed:',
            style: Theme.of(context).textTheme.titleSmall,
          ),
          const SizedBox(height: 12),

          const _DestroyItem(
            icon: Icons.key_off_outlined,
            label: 'Identity keys',
            description: 'Your cryptographic key pair will be overwritten',
          ),
          const _DestroyItem(
            icon: Icons.map_outlined,
            label: 'Network map',
            description: 'All known peer routes and relay data',
          ),
          const _DestroyItem(
            icon: Icons.chat_bubble_outline,
            label: 'Message history',
            description: 'All conversations and messages',
          ),
          const _DestroyItem(
            icon: Icons.person_off_outlined,
            label: 'Profile data',
            description: 'Public and private profile information',
          ),
          const _DestroyItem(
            icon: Icons.cached_outlined,
            label: 'All cached data',
            description: 'Temporary files, session tokens, and local state',
          ),

          const SizedBox(height: 24),

          // Acknowledgement checkbox
          CheckboxListTile(
            contentPadding: EdgeInsets.zero,
            controlAffinity: ListTileControlAffinity.leading,
            title: const Text('I understand this is irreversible'),
            value: _acknowledged,
            onChanged: (v) => setState(() => _acknowledged = v ?? false),
          ),

          const SizedBox(height: 16),

          // Destroy button
          FilledButton.icon(
            onPressed: (_acknowledged && !_busy) ? _onDestroy : null,
            style: FilledButton.styleFrom(
              backgroundColor: cs.error,
              foregroundColor: cs.onError,
              minimumSize: const Size.fromHeight(52),
            ),
            icon: _busy
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(
                      strokeWidth: 2,
                      color: Colors.white,
                    ),
                  )
                : const Icon(Icons.delete_forever_outlined),
            label: Text(_busy ? 'Destroying...' : 'DESTROY ALL DATA'),
          ),
        ],
      ),
    );
  }
}

/// A single bullet-point item describing what will be destroyed.
class _DestroyItem extends StatelessWidget {
  const _DestroyItem({
    required this.icon,
    required this.label,
    required this.description,
  });

  final IconData icon;
  final String label;
  final String description;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          Icon(icon, size: 20, color: Theme.of(context).colorScheme.error),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(label,
                    style: Theme.of(context)
                        .textTheme
                        .bodyMedium
                        ?.copyWith(fontWeight: FontWeight.w600)),
                Text(description,
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        )),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

/// Dialog that requires the user to type "DELETE" to confirm destruction.
class _ConfirmDeleteDialog extends StatefulWidget {
  @override
  State<_ConfirmDeleteDialog> createState() => _ConfirmDeleteDialogState();
}

class _ConfirmDeleteDialogState extends State<_ConfirmDeleteDialog> {
  final _ctl = TextEditingController();
  bool get _isValid => _ctl.text.trim().toUpperCase() == 'DELETE';

  @override
  void dispose() {
    _ctl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    return AlertDialog(
      title: const Text('Final Confirmation'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Text('Type DELETE to confirm data destruction.'),
          const SizedBox(height: 12),
          TextField(
            controller: _ctl,
            autofocus: true,
            decoration: const InputDecoration(
              hintText: 'DELETE',
            ),
            onChanged: (_) => setState(() {}),
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context, false),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: _isValid ? () => Navigator.pop(context, true) : null,
          style: FilledButton.styleFrom(
            backgroundColor: cs.error,
            foregroundColor: cs.onError,
          ),
          child: const Text('Destroy'),
        ),
      ],
    );
  }
}
