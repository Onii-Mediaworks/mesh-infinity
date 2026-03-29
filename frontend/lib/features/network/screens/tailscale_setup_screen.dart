import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';
import '../network_state.dart';

/// TailscaleSetupScreen — first-class Tailscale / Headscale client setup.
///
/// Mesh Infinity IS the Tailscale client. On mobile, this fills the single
/// VPN slot so users don't need a separate Tailscale app. On desktop it
/// manages its own interface alongside or instead of the system daemon.
///
/// Auth flow: OAuth via in-app browser (tailscale.com or Headscale URL),
/// or a pre-auth key for headless/server enrollment.
class TailscaleSetupScreen extends StatefulWidget {
  const TailscaleSetupScreen({super.key});

  @override
  State<TailscaleSetupScreen> createState() => _TailscaleSetupScreenState();
}

class _TailscaleSetupScreenState extends State<TailscaleSetupScreen> {
  // Which controller type is selected.
  _ControllerType _controllerType = _ControllerType.tailscaleVendor;

  // Headscale URL controller.
  final _headscaleUrlCtrl = TextEditingController();

  // Auth key for headless enrollment.
  final _authKeyCtrl = TextEditingController();

  bool _useAuthKey = false;
  bool _connecting = false;
  String? _errorMessage;

  @override
  void dispose() {
    _headscaleUrlCtrl.dispose();
    _authKeyCtrl.dispose();
    super.dispose();
  }

  Future<void> _connect() async {
    setState(() {
      _connecting = true;
      _errorMessage = null;
    });

    final net = context.read<NetworkState>();
    final bridge = context.read<BackendBridge>();

    final controlUrl = _controllerType == _ControllerType.headscale
        ? _headscaleUrlCtrl.text.trim()
        : '';

    try {
      net.setOverlayClientStatus('tailscale', OverlayClientStatus.connecting);

      bool ok;
      if (_useAuthKey) {
        final key = _authKeyCtrl.text.trim();
        if (key.isEmpty) throw Exception('Auth key is required');
        ok = bridge.tailscaleAuthKey(key, controlUrl);
      } else {
        ok = bridge.tailscaleBeginOAuth(controlUrl);
      }

      if (!ok) {
        throw Exception(bridge.getLastError() ?? 'Tailscale connection failed');
      }

      net.setOverlayClientStatus('tailscale', OverlayClientStatus.connected);

      if (mounted) {
        Navigator.of(context).pop();
      }
    } catch (e) {
      net.setOverlayClientStatus('tailscale', OverlayClientStatus.error);
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
      appBar: AppBar(title: const Text('Tailscale')),
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
              'Mesh Infinity acts as your Tailscale client — no separate app '
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
                value: _ControllerType.tailscaleVendor,
                label: Text('Tailscale'),
                icon: Icon(Icons.cloud_outlined),
              ),
              ButtonSegment(
                value: _ControllerType.headscale,
                label: Text('Headscale'),
                icon: Icon(Icons.dns_outlined),
              ),
            ],
            selected: {_controllerType},
            onSelectionChanged: (s) =>
                setState(() => _controllerType = s.first),
          ),

          if (_controllerType == _ControllerType.headscale) ...[
            const SizedBox(height: 16),
            TextField(
              controller: _headscaleUrlCtrl,
              decoration: const InputDecoration(
                labelText: 'Headscale server URL',
                hintText: 'https://headscale.example.com',
                border: OutlineInputBorder(),
                prefixIcon: Icon(Icons.link_outlined),
              ),
              keyboardType: TextInputType.url,
              autocorrect: false,
            ),
          ],

          const SizedBox(height: 24),

          // Auth method
          Text('Authentication', style: tt.labelLarge),
          const SizedBox(height: 8),
          SwitchListTile(
            contentPadding: EdgeInsets.zero,
            title: const Text('Use auth key'),
            subtitle: const Text(
                'For headless or server nodes. Generate in the admin panel.'),
            value: _useAuthKey,
            onChanged: (v) => setState(() => _useAuthKey = v),
          ),

          if (_useAuthKey) ...[
            const SizedBox(height: 8),
            TextField(
              controller: _authKeyCtrl,
              decoration: const InputDecoration(
                labelText: 'Auth key',
                hintText: 'tskey-auth-...',
                border: OutlineInputBorder(),
                prefixIcon: Icon(Icons.key_outlined),
              ),
              obscureText: true,
              autocorrect: false,
            ),
          ] else ...[
            const SizedBox(height: 8),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: cs.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: cs.outlineVariant),
              ),
              child: Row(
                children: [
                  Icon(Icons.info_outline, size: 16, color: cs.onSurfaceVariant),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'Tapping Sign in will open the '
                      '${_controllerType == _ControllerType.headscale ? "Headscale" : "Tailscale"} '
                      'login page. Complete sign-in to authorise this device.',
                      style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
                    ),
                  ),
                ],
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
                  Icon(Icons.error_outline, size: 16, color: cs.onErrorContainer),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      _errorMessage!,
                      style: tt.bodySmall?.copyWith(color: cs.onErrorContainer),
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
                : Icon(_useAuthKey ? Icons.link_outlined : Icons.login_outlined),
            label: Text(_useAuthKey ? 'Enrol with key' : 'Sign in'),
            style: FilledButton.styleFrom(
              minimumSize: const Size(double.infinity, 48),
            ),
          ),

          const SizedBox(height: 12),

          // Security note
          Text(
            'Tailscale anonymization score: 0.3 (vendor coordination server) '
            '· Headscale: 0.5 (self-hosted). '
            'Clearnet traffic routed via Tailscale exit nodes is visible to '
            'the exit node operator. Mesh traffic remains end-to-end encrypted.',
            style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }
}

enum _ControllerType { tailscaleVendor, headscale }
