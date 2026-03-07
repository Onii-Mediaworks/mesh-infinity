import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../peers_state.dart';
import '../widgets/qr_pairing_widget.dart';

class PairPeerScreen extends StatefulWidget {
  const PairPeerScreen({super.key});

  @override
  State<PairPeerScreen> createState() => _PairPeerScreenState();
}

class _PairPeerScreenState extends State<PairPeerScreen>
    with SingleTickerProviderStateMixin {
  late final TabController _tabs = TabController(length: 2, vsync: this);
  final _codeController = TextEditingController();
  bool _pairing = false;

  @override
  void dispose() {
    _tabs.dispose();
    _codeController.dispose();
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
        const SnackBar(content: Text('Pairing failed. Check the code and try again.')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Pair with Peer'),
        bottom: TabBar(
          controller: _tabs,
          tabs: const [
            Tab(icon: Icon(Icons.qr_code_scanner), text: 'Scan QR'),
            Tab(icon: Icon(Icons.keyboard_outlined), text: 'Enter Code'),
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
              ],
            ),
    );
  }
}

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
