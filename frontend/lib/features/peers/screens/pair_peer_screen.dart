import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';
import '../../../backend/models/settings_models.dart';
import '../peers_state.dart';
import '../widgets/qr_pairing_widget.dart';

class PairPeerScreen extends StatefulWidget {
  const PairPeerScreen({super.key});

  @override
  State<PairPeerScreen> createState() => _PairPeerScreenState();
}

class _PairPeerScreenState extends State<PairPeerScreen>
    with SingleTickerProviderStateMixin {
  late final TabController _tabs = TabController(length: 4, vsync: this);
  final _codeController = TextEditingController();
  final _linkImportController = TextEditingController();
  final _keyImportController = TextEditingController();
  bool _pairing = false;

  @override
  void dispose() {
    _tabs.dispose();
    _codeController.dispose();
    _linkImportController.dispose();
    _keyImportController.dispose();
    super.dispose();
  }

  Future<void> _pair(String code) async {
    if (code.trim().isEmpty) return;
    setState(() => _pairing = true);
    final ok = await context.read<PeersState>().pairPeer(code.trim());
    if (!mounted) return;
    if (ok) {
      Navigator.pop(context, true);
    } else {
      setState(() => _pairing = false);
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
            content: Text('Pairing failed. Check the code and try again.')),
      );
    }
  }

  /// Parse a deep link URL and extract the pairing token, then initiate pairing.
  Future<void> _importLink(String linkText) async {
    final text = linkText.trim();
    if (text.isEmpty) return;

    final uri = Uri.tryParse(text);
    if (uri == null ||
        uri.scheme != 'meshinfinity' ||
        uri.host != 'pair') {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
            content: Text(
                'Invalid link. Expected meshinfinity://pair?... format.')),
      );
      return;
    }

    final peerId = uri.queryParameters['peer_id'];
    final token = uri.queryParameters['token'];
    if (peerId == null || peerId.isEmpty || token == null || token.isEmpty) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
            content: Text('Link is missing required peer_id or token.')),
      );
      return;
    }

    // The pairing flow accepts the token string.
    await _pair(token);
  }

  /// Parse a key block and extract the peer ID for pairing.
  Future<void> _importKey(String keyText) async {
    final text = keyText.trim();
    if (text.isEmpty) return;

    if (!text.contains('--- BEGIN MESH INFINITY PUBLIC KEY ---') ||
        !text.contains('--- END MESH INFINITY PUBLIC KEY ---')) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
            content:
                Text('Invalid key block. Check the format and try again.')),
      );
      return;
    }

    // Extract the Peer-ID line.
    final peerIdMatch =
        RegExp(r'Peer-ID:\s*([0-9a-fA-F]+)').firstMatch(text);
    if (peerIdMatch == null) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Could not find Peer-ID in key block.')),
      );
      return;
    }

    final peerId = peerIdMatch.group(1)!;
    await _pair(peerId);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Pair with Peer'),
        bottom: TabBar(
          controller: _tabs,
          tabs: const [
            Tab(icon: Icon(Icons.qr_code_scanner), text: 'Scan'),
            Tab(icon: Icon(Icons.keyboard_outlined), text: 'Code'),
            Tab(icon: Icon(Icons.link), text: 'Link'),
            Tab(icon: Icon(Icons.key_outlined), text: 'Key'),
          ],
        ),
      ),
      body: _pairing
          ? const Center(child: CircularProgressIndicator())
          : TabBarView(
              controller: _tabs,
              children: [
                _ScanTab(onScanned: _pair),
                _CodeTab(controller: _codeController, onPair: _pair),
                _LinkTab(
                  controller: _linkImportController,
                  onImportLink: _importLink,
                ),
                _KeyTab(
                  controller: _keyImportController,
                  onImportKey: _importKey,
                ),
              ],
            ),
    );
  }
}

// ---------------------------------------------------------------------------
// Scan tab (unchanged)
// ---------------------------------------------------------------------------

class _ScanTab extends StatelessWidget {
  const _ScanTab({required this.onScanned});

  final ValueChanged<String> onScanned;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        children: [
          Expanded(child: QrPairingWidget(onScanned: onScanned)),
          const SizedBox(height: 16),
          Text(
            'Point the camera at your peer\'s QR code',
            style: Theme.of(context).textTheme.bodySmall?.copyWith(
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Code tab (unchanged)
// ---------------------------------------------------------------------------

class _CodeTab extends StatelessWidget {
  const _CodeTab({required this.controller, required this.onPair});

  final TextEditingController controller;
  final ValueChanged<String> onPair;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          TextField(
            controller: controller,
            autofocus: true,
            decoration: const InputDecoration(
              labelText: 'Pairing code',
              hintText: 'Paste or type the peer\'s pairing code',
            ),
            onSubmitted: onPair,
          ),
          const SizedBox(height: 24),
          FilledButton(
            onPressed: () => onPair(controller.text),
            child: const Text('Pair'),
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Link tab
// ---------------------------------------------------------------------------

class _LinkTab extends StatelessWidget {
  const _LinkTab({
    required this.controller,
    required this.onImportLink,
  });

  final TextEditingController controller;
  final ValueChanged<String> onImportLink;

  @override
  Widget build(BuildContext context) {
    final bridge = context.read<BackendBridge>();

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // --- Share section ---
          Text(
            'Share your pairing link',
            style: Theme.of(context).textTheme.titleSmall,
          ),
          const SizedBox(height: 12),
          _PairingLinkDisplay(bridge: bridge),
          const SizedBox(height: 32),
          const Divider(),
          const SizedBox(height: 24),
          // --- Import section ---
          Text(
            'Import a peer\'s link',
            style: Theme.of(context).textTheme.titleSmall,
          ),
          const SizedBox(height: 12),
          TextField(
            controller: controller,
            maxLines: 2,
            decoration: const InputDecoration(
              labelText: 'Pairing link',
              hintText: 'Paste meshinfinity://pair?... link here',
            ),
            onSubmitted: onImportLink,
          ),
          const SizedBox(height: 16),
          FilledButton.icon(
            onPressed: () => onImportLink(controller.text),
            icon: const Icon(Icons.download_outlined),
            label: const Text('Import Link'),
          ),
        ],
      ),
    );
  }
}

class _PairingLinkDisplay extends StatelessWidget {
  const _PairingLinkDisplay({required this.bridge});

  final BackendBridge bridge;

  String _buildLink(LocalIdentitySummary identity, SettingsModel? settings) {
    final peerId = identity.peerId;
    final token = settings?.pairingCode ?? peerId;
    final params = <String, String>{
      'v': '1',
      'peer_id': peerId,
      'token': token,
    };
    if (identity.name != null && identity.name!.isNotEmpty) {
      params['name'] = identity.name!;
    }
    final uri = Uri(
      scheme: 'meshinfinity',
      host: 'pair',
      queryParameters: params,
    );
    return uri.toString();
  }

  @override
  Widget build(BuildContext context) {
    final identity = bridge.fetchLocalIdentity();
    if (identity == null) {
      return const Text('Identity not available.');
    }

    final settings = bridge.fetchSettings();
    final link = _buildLink(identity, settings);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.surfaceContainerHighest,
            borderRadius: BorderRadius.circular(8),
          ),
          child: SelectableText(
            link,
            style: Theme.of(context).textTheme.bodySmall?.copyWith(
              fontFamily: 'monospace',
            ),
          ),
        ),
        const SizedBox(height: 12),
        FilledButton.tonalIcon(
          onPressed: () {
            Clipboard.setData(ClipboardData(text: link));
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(content: Text('Pairing link copied.')),
            );
          },
          icon: const Icon(Icons.copy),
          label: const Text('Copy Link'),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// Key tab
// ---------------------------------------------------------------------------

class _KeyTab extends StatelessWidget {
  const _KeyTab({
    required this.controller,
    required this.onImportKey,
  });

  final TextEditingController controller;
  final ValueChanged<String> onImportKey;

  @override
  Widget build(BuildContext context) {
    final bridge = context.read<BackendBridge>();

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // --- Export section ---
          Text(
            'Your public key',
            style: Theme.of(context).textTheme.titleSmall,
          ),
          const SizedBox(height: 12),
          _PublicKeyDisplay(bridge: bridge),
          const SizedBox(height: 32),
          const Divider(),
          const SizedBox(height: 24),
          // --- Import section ---
          Text(
            'Import a peer\'s key',
            style: Theme.of(context).textTheme.titleSmall,
          ),
          const SizedBox(height: 12),
          TextField(
            controller: controller,
            maxLines: 6,
            decoration: const InputDecoration(
              labelText: 'Public key block',
              hintText:
                  'Paste the full key block from --- BEGIN to --- END',
              alignLabelWithHint: true,
            ),
          ),
          const SizedBox(height: 16),
          FilledButton.icon(
            onPressed: () => onImportKey(controller.text),
            icon: const Icon(Icons.download_outlined),
            label: const Text('Import Key'),
          ),
        ],
      ),
    );
  }
}

class _PublicKeyDisplay extends StatelessWidget {
  const _PublicKeyDisplay({required this.bridge});

  final BackendBridge bridge;

  String _buildKeyBlock(LocalIdentitySummary identity) {
    final buf = StringBuffer()
      ..writeln('--- BEGIN MESH INFINITY PUBLIC KEY ---')
      ..writeln('Peer-ID: ${identity.peerId}');

    // The publicKey field from the backend may contain both Ed25519 and X25519
    // keys separated by a colon, or a single key. Adapt display accordingly.
    final parts = identity.publicKey.split(':');
    if (parts.length >= 2) {
      buf
        ..writeln('Ed25519: ${parts[0]}')
        ..writeln('X25519: ${parts[1]}');
    } else {
      // Single key — show as Ed25519 (signing key) and derive note.
      buf
        ..writeln('Ed25519: ${identity.publicKey}')
        ..writeln('X25519: <derived from Ed25519>');
    }

    buf.write('--- END MESH INFINITY PUBLIC KEY ---');
    return buf.toString();
  }

  @override
  Widget build(BuildContext context) {
    final identity = bridge.fetchLocalIdentity();
    if (identity == null) {
      return const Text('Identity not available.');
    }

    final keyBlock = _buildKeyBlock(identity);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.surfaceContainerHighest,
            borderRadius: BorderRadius.circular(8),
          ),
          child: SelectableText(
            keyBlock,
            style: Theme.of(context).textTheme.bodySmall?.copyWith(
              fontFamily: 'monospace',
              height: 1.6,
            ),
          ),
        ),
        const SizedBox(height: 12),
        FilledButton.tonalIcon(
          onPressed: () {
            Clipboard.setData(ClipboardData(text: keyBlock));
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(content: Text('Public key copied.')),
            );
          },
          icon: const Icon(Icons.copy),
          label: const Text('Copy Key'),
        ),
      ],
    );
  }
}
