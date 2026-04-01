import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';
import '../settings_state.dart';

// ---------------------------------------------------------------------------
// NodeScreen — node mode, clearnet port, and pairing code.
// ---------------------------------------------------------------------------

class NodeScreen extends StatefulWidget {
  const NodeScreen({super.key});

  @override
  State<NodeScreen> createState() => _NodeScreenState();
}

class _NodeScreenState extends State<NodeScreen> {
  int _nodeMode = 0;
  final _portController = TextEditingController();
  bool _saving = false;

  @override
  void initState() {
    super.initState();
    final s = context.read<SettingsState>().settings;
    if (s != null) {
      _nodeMode = s.nodeMode;
      _portController.text = s.clearnetPort.toString();
    }
  }

  @override
  void dispose() {
    _portController.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    final port = int.tryParse(_portController.text.trim());
    if (port == null || port < 1024 || port > 65535) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Port must be between 1024 and 65535')),
      );
      return;
    }
    setState(() => _saving = true);
    final bridge = context.read<BackendBridge>();
    final modeOk = bridge.setNodeMode(_nodeMode);
    final portOk = bridge.setClearnetPort(port);
    if (mounted) {
      setState(() => _saving = false);
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content: Text(
          (modeOk && portOk) ? 'Node settings saved' : 'Failed to save settings',
        ),
      ));
    }
    if (modeOk && portOk && mounted) {
      await context.read<SettingsState>().loadAll();
    }
  }

  @override
  Widget build(BuildContext context) {
    final settings = context.watch<SettingsState>();
    final s = settings.settings;
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Node'),
        actions: [
          if (_saving)
            const Padding(
              padding: EdgeInsets.all(14),
              child: SizedBox(
                width: 20,
                height: 20,
                child: CircularProgressIndicator(strokeWidth: 2),
              ),
            )
          else
            TextButton(onPressed: _save, child: const Text('Save')),
        ],
      ),
      body: ListView(
        children: [
          // ── Node mode ───────────────────────────────────────────────
          const _SectionHeader('Node mode'),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
            child: Text(
              'Controls how this device participates in the mesh network.',
              style: theme.textTheme.bodySmall?.copyWith(
                color: cs.onSurfaceVariant,
              ),
            ),
          ),
          RadioGroup<int>(
            groupValue: _nodeMode,
            onChanged: (v) {
              if (v != null) setState(() => _nodeMode = v);
            },
            child: const Column(
              children: [
                RadioListTile<int>(
                  secondary: Icon(Icons.device_hub_outlined),
                  title: Text('Client'),
                  subtitle: Text(
                    'Connects to the mesh but does not route traffic for others',
                  ),
                  value: 0,
                ),
                RadioListTile<int>(
                  secondary: Icon(Icons.router_outlined),
                  title: Text('Server'),
                  subtitle: Text(
                    'Routes traffic for other nodes; requires stable connectivity',
                  ),
                  value: 1,
                ),
                RadioListTile<int>(
                  secondary: Icon(Icons.hub_outlined),
                  title: Text('Dual'),
                  subtitle: Text(
                    'Full participant — routes traffic and originates messages',
                  ),
                  value: 2,
                ),
              ],
            ),
          ),
          const Divider(height: 1),

          // ── Clearnet port ───────────────────────────────────────────
          const _SectionHeader('Clearnet transport'),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 4, 16, 16),
            child: TextField(
              controller: _portController,
              keyboardType: TextInputType.number,
              inputFormatters: [FilteringTextInputFormatter.digitsOnly],
              decoration: const InputDecoration(
                labelText: 'TCP listen port',
                hintText: '7234',
                helperText: 'Port range 1024–65535. Default: 7234.',
              ),
            ),
          ),
          const Divider(height: 1),

          // ── Pairing code ────────────────────────────────────────────
          const _SectionHeader('Pairing'),
          if (s != null && (s.pairingCode?.isNotEmpty ?? false))
            ListTile(
              leading: const Icon(Icons.qr_code_2_outlined),
              title: const Text('Pairing code'),
              subtitle: Text(s.pairingCode!),
              trailing: IconButton(
                icon: const Icon(Icons.copy_outlined),
                tooltip: 'Copy pairing code',
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: s.pairingCode!));
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Pairing code copied')),
                  );
                },
              ),
            )
          else
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
              child: Text(
                'No pairing code configured. The backend will generate one '
                'on first peer pairing.',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: cs.onSurfaceVariant,
                ),
              ),
            ),
          const SizedBox(height: 24),
        ],
      ),
    );
  }
}

class _SectionHeader extends StatelessWidget {
  const _SectionHeader(this.title);
  final String title;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 20, 16, 6),
      child: Text(
        title,
        style: Theme.of(context).textTheme.labelMedium?.copyWith(
              color: Theme.of(context).colorScheme.primary,
              fontWeight: FontWeight.w700,
              letterSpacing: 0.8,
            ),
      ),
    );
  }
}
