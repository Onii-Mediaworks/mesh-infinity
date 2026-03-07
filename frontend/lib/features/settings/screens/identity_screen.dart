import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../settings_state.dart';

class IdentityScreen extends StatelessWidget {
  const IdentityScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final identity = context.watch<SettingsState>().identity;
    final cs = Theme.of(context).colorScheme;

    return Scaffold(
      appBar: AppBar(title: const Text('Identity')),
      body: identity == null
          ? const Center(child: Text('Identity not available'))
          : ListView(
              padding: const EdgeInsets.all(16),
              children: [
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(20),
                    child: Column(
                      children: [
                        Container(
                          decoration: BoxDecoration(
                            color: Colors.white,
                            borderRadius: BorderRadius.circular(12),
                          ),
                          padding: const EdgeInsets.all(8),
                          child: QrImageView(
                            data: identity.peerId,
                            version: QrVersions.auto,
                            size: 200,
                            eyeStyle: QrEyeStyle(
                              eyeShape: QrEyeShape.square,
                              color: cs.primary,
                            ),
                          ),
                        ),
                        const SizedBox(height: 12),
                        Text(
                          'Share your QR code for others to pair with you',
                          style: Theme.of(context).textTheme.bodySmall?.copyWith(
                            color: cs.onSurfaceVariant,
                          ),
                          textAlign: TextAlign.center,
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 12),
                _KeyCard(
                  label: 'Peer ID',
                  value: identity.peerId,
                  onCopy: () => _copy(context, identity.peerId, 'Peer ID'),
                ),
                const SizedBox(height: 8),
                _KeyCard(
                  label: 'Public Key',
                  value: identity.publicKey,
                  onCopy: () => _copy(context, identity.publicKey, 'Public key'),
                ),
                if (identity.name != null) ...[
                  const SizedBox(height: 8),
                  Card(
                    child: ListTile(
                      title: const Text('Display Name'),
                      subtitle: Text(identity.name!),
                      leading: const Icon(Icons.person_outline),
                    ),
                  ),
                ],
              ],
            ),
    );
  }

  void _copy(BuildContext context, String value, String label) {
    Clipboard.setData(ClipboardData(text: value));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('$label copied')),
    );
  }
}

class _KeyCard extends StatelessWidget {
  const _KeyCard({
    required this.label,
    required this.value,
    required this.onCopy,
  });

  final String label;
  final String value;
  final VoidCallback onCopy;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Text(label, style: Theme.of(context).textTheme.titleSmall),
                const Spacer(),
                IconButton(
                  icon: const Icon(Icons.copy_outlined, size: 18),
                  tooltip: 'Copy',
                  onPressed: onCopy,
                  visualDensity: VisualDensity.compact,
                ),
              ],
            ),
            const SizedBox(height: 8),
            SelectableText(
              value,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
            ),
          ],
        ),
      ),
    );
  }
}
