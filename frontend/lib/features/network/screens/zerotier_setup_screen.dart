import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';
import '../network_state.dart';

/// ZeroTierSetupScreen — first-class ZeroTier client setup.
///
/// Mesh Infinity IS the ZeroTier client. Authenticates via API key from
/// ZeroTier Central (my.zerotier.com) or a self-hosted controller.
/// Users join networks by ID; Mesh Infinity handles enrollment and
/// member authorization automatically for auto-join networks.
class ZeroTierSetupScreen extends StatefulWidget {
  const ZeroTierSetupScreen({super.key});

  @override
  State<ZeroTierSetupScreen> createState() => _ZeroTierSetupScreenState();
}

class _ZeroTierSetupScreenState extends State<ZeroTierSetupScreen> {
  _ControllerType _controllerType = _ControllerType.central;

  final _apiKeyCtrl = TextEditingController();
  final _controllerUrlCtrl = TextEditingController();
  final _networkIdCtrl = TextEditingController();

  bool _connecting = false;
  String? _errorMessage;

  // Networks that have been joined this session (before saving).
  final List<String> _pendingNetworks = [];

  @override
  void dispose() {
    _apiKeyCtrl.dispose();
    _controllerUrlCtrl.dispose();
    _networkIdCtrl.dispose();
    super.dispose();
  }

  void _addNetwork() {
    final id = _networkIdCtrl.text.trim();
    if (id.isEmpty) return;
    // ZeroTier network IDs are 16 hex characters.
    final validId = RegExp(r'^[0-9a-fA-F]{16}$').hasMatch(id);
    if (!validId) {
      setState(() => _errorMessage = 'Network ID must be 16 hex characters');
      return;
    }
    if (_pendingNetworks.contains(id)) return;
    setState(() {
      _pendingNetworks.add(id);
      _networkIdCtrl.clear();
      _errorMessage = null;
    });
  }

  Future<void> _connect() async {
    final apiKey = _apiKeyCtrl.text.trim();
    if (apiKey.isEmpty) {
      setState(() => _errorMessage = 'API key is required');
      return;
    }
    if (_pendingNetworks.isEmpty) {
      setState(() => _errorMessage = 'Add at least one network ID to join');
      return;
    }

    setState(() {
      _connecting = true;
      _errorMessage = null;
    });

    final net = context.read<NetworkState>();
    final bridge = context.read<BackendBridge>();

    final controllerUrl = _controllerType == _ControllerType.selfHosted
        ? _controllerUrlCtrl.text.trim()
        : '';

    try {
      net.setOverlayClientStatus('zerotier', OverlayClientStatus.connecting);

      final ok = bridge.zerotierConnect(apiKey, controllerUrl, List.from(_pendingNetworks));
      if (!ok) {
        throw Exception(bridge.getLastError() ?? 'ZeroTier connection failed');
      }

      net.setOverlayClientStatus('zerotier', OverlayClientStatus.connected);

      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      net.setOverlayClientStatus('zerotier', OverlayClientStatus.error);
      setState(() {
        _errorMessage = e.toString().replaceFirst('Exception: ', '');
      });
    } finally {
      if (mounted) setState(() => _connecting = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    return Scaffold(
      appBar: AppBar(title: const Text('ZeroTier')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // Explanation
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: cs.primaryContainer.withValues(alpha: 0.3),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Text(
              'Mesh Infinity acts as your ZeroTier client — no separate app '
              'needed. On mobile, it shares the VPN slot with mesh routing.',
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            ),
          ),
          const SizedBox(height: 24),

          // Controller type
          Text('Controller', style: tt.labelLarge),
          const SizedBox(height: 8),
          SegmentedButton<_ControllerType>(
            segments: const [
              ButtonSegment(
                value: _ControllerType.central,
                label: Text('ZeroTier Central'),
                icon: Icon(Icons.cloud_outlined),
              ),
              ButtonSegment(
                value: _ControllerType.selfHosted,
                label: Text('Self-hosted'),
                icon: Icon(Icons.dns_outlined),
              ),
            ],
            selected: {_controllerType},
            onSelectionChanged: (s) =>
                setState(() => _controllerType = s.first),
          ),

          if (_controllerType == _ControllerType.selfHosted) ...[
            const SizedBox(height: 16),
            TextField(
              controller: _controllerUrlCtrl,
              decoration: const InputDecoration(
                labelText: 'Controller URL',
                hintText: 'https://zt.example.com',
                border: OutlineInputBorder(),
                prefixIcon: Icon(Icons.link_outlined),
              ),
              keyboardType: TextInputType.url,
              autocorrect: false,
            ),
          ],

          const SizedBox(height: 24),

          // API key
          Text('API Key', style: tt.labelLarge),
          const SizedBox(height: 4),
          Text(
            _controllerType == _ControllerType.central
                ? 'Generate at my.zerotier.com → Account → API Access Tokens'
                : 'Generate in your controller admin panel',
            style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: _apiKeyCtrl,
            decoration: const InputDecoration(
              labelText: 'API key',
              hintText: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
              border: OutlineInputBorder(),
              prefixIcon: Icon(Icons.key_outlined),
            ),
            obscureText: true,
            autocorrect: false,
          ),

          const SizedBox(height: 24),

          // Network IDs
          Text('Networks to Join', style: tt.labelLarge),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: _networkIdCtrl,
                  decoration: const InputDecoration(
                    labelText: 'Network ID',
                    hintText: '8056c2e21c000001',
                    border: OutlineInputBorder(),
                    prefixIcon: Icon(Icons.lan_outlined),
                  ),
                  maxLength: 16,
                  autocorrect: false,
                  onSubmitted: (_) => _addNetwork(),
                ),
              ),
              const SizedBox(width: 8),
              FilledButton.tonal(
                onPressed: _addNetwork,
                child: const Text('Add'),
              ),
            ],
          ),

          if (_pendingNetworks.isNotEmpty) ...[
            const SizedBox(height: 8),
            for (final id in _pendingNetworks)
              ListTile(
                dense: true,
                leading: const Icon(Icons.lan_outlined, size: 18),
                title: Text(id,
                    style: const TextStyle(fontFamily: 'monospace')),
                trailing: IconButton(
                  icon: const Icon(Icons.close, size: 18),
                  onPressed: () =>
                      setState(() => _pendingNetworks.remove(id)),
                ),
              ),
          ],

          if (_errorMessage != null) ...[
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: cs.errorContainer,
                borderRadius: BorderRadius.circular(8),
              ),
              child: Row(
                children: [
                  Icon(Icons.error_outline,
                      size: 16, color: cs.onErrorContainer),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      _errorMessage!,
                      style: tt.bodySmall
                          ?.copyWith(color: cs.onErrorContainer),
                    ),
                  ),
                ],
              ),
            ),
          ],

          const SizedBox(height: 24),

          FilledButton.icon(
            onPressed: _connecting ? null : _connect,
            icon: _connecting
                ? const SizedBox(
                    width: 16,
                    height: 16,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.link_outlined),
            label: const Text('Connect'),
            style: FilledButton.styleFrom(
              minimumSize: const Size(double.infinity, 48),
            ),
          ),

          const SizedBox(height: 12),

          Text(
            'ZeroTier anonymization score: 0.3 (vendor coordination server) '
            '· Self-hosted: 0.5. '
            'Private networks require admin approval — your Node ID will be '
            'shown to the network admin.',
            style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }
}

enum _ControllerType { central, selfHosted }
