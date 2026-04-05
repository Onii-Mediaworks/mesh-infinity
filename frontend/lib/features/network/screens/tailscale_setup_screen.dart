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
      await net.loadAll();
    } catch (e) {
      setState(() {
        _errorMessage = e.toString().replaceFirst('Exception: ', '');
      });
    } finally {
      if (mounted) setState(() => _connecting = false);
    }
  }

  Future<void> _refresh(NetworkState net, BackendBridge bridge) async {
    setState(() => _connecting = true);
    final ok = bridge.tailscaleRefresh();
    await net.loadAll();
    if (!ok && mounted) {
      setState(() {
        _errorMessage = bridge.getLastError() ?? 'Could not refresh Tailscale';
      });
    }
    if (mounted) {
      setState(() => _connecting = false);
    }
  }

  Future<void> _disconnect(NetworkState net, BackendBridge bridge) async {
    setState(() => _connecting = true);
    final ok = bridge.tailscaleDisconnect();
    await net.loadAll();
    if (!ok && mounted) {
      setState(() {
        _errorMessage = bridge.getLastError() ?? 'Could not disconnect Tailscale';
      });
    }
    if (mounted) {
      setState(() => _connecting = false);
    }
  }

  Future<void> _setPreferMeshRelay(
    NetworkState net,
    BackendBridge bridge,
    bool enabled,
  ) async {
    final ok = bridge.tailscaleSetPreferMeshRelay(enabled);
    await net.loadAll();
    if (!ok && mounted) {
      setState(() {
        _errorMessage =
            bridge.getLastError() ?? 'Could not update relay preference';
      });
    }
  }

  Future<void> _setExitNode(
    NetworkState net,
    BackendBridge bridge,
    String peerName,
  ) async {
    final ok = bridge.tailscaleSetExitNode(peerName);
    await net.loadAll();
    if (!ok && mounted) {
      setState(() {
        _errorMessage = bridge.getLastError() ?? 'Could not update exit node';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;
    final net = context.watch<NetworkState>();
    final bridge = context.read<BackendBridge>();
    final overlay = net.tailscaleOverlay;
    final deviceIp = overlay['deviceIp'] as String?;
    final deviceName = overlay['deviceName'] as String?;
    final tailnetName = overlay['tailnetName'] as String?;
    final os = overlay['os'] as String?;
    final controller = overlay['controller'] as String?;
    final preferMeshRelay = overlay['preferMeshRelay'] == true;
    final activeExitNode = overlay['exitNode'] as String?;
    final relayMode = overlay['relayMode'] as String?;
    final keyExpiryUnixMs = overlay['keyExpiryUnixMs'] as int? ?? 0;
    final peers = (overlay['peers'] as List?)
            ?.whereType<Map>()
            .map((entry) => Map<String, dynamic>.from(entry))
            .toList() ??
        const <Map<String, dynamic>>[];
    final exitNodes = (overlay['exitNodes'] as List?)
            ?.whereType<Map>()
            .map((entry) => Map<String, dynamic>.from(entry))
            .toList() ??
        const <Map<String, dynamic>>[];
    final isConfigured =
        net.tailscaleClientStatus != OverlayClientStatus.notConfigured;

    return Scaffold(
      appBar: AppBar(title: const Text('Tailscale')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: cs.primaryContainer.withValues(alpha: 0.3),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Text(
              'Mesh Infinity acts as your Tailscale client for an existing '
              'tailnet — no separate app needed. On mobile, it shares the VPN '
              'slot with mesh routing.',
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            ),
          ),
          const SizedBox(height: 24),
          _StatusCard(
            title: 'Status',
            lines: [
              _statusLabel(net.tailscaleClientStatus),
              if (deviceName != null && deviceName.isNotEmpty) deviceName,
              if (deviceIp != null && deviceIp.isNotEmpty) deviceIp,
              if (os != null && os.isNotEmpty) os,
              if (tailnetName != null && tailnetName.isNotEmpty) tailnetName,
              if (controller != null && controller.isNotEmpty) controller,
              if (relayMode != null && relayMode.isNotEmpty)
                'Relay: ${_relayModeLabel(relayMode)}',
              if (keyExpiryUnixMs > 0)
                'Key expiry: ${DateTime.fromMillisecondsSinceEpoch(keyExpiryUnixMs).toLocal()}',
            ],
          ),

          if (isConfigured) ...[
            const SizedBox(height: 16),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text('Prefer mesh relay over Tailscale relay'),
              subtitle: const Text(
                'Avoid Tailscale relay infrastructure when a mesh relay path is available.',
              ),
              value: preferMeshRelay,
              onChanged: _connecting
                  ? null
                  : (value) => _setPreferMeshRelay(net, bridge, value),
            ),
            const SizedBox(height: 8),
            Row(
              children: [
                Expanded(
                  child: FilledButton.tonalIcon(
                    onPressed: _connecting ? null : () => _refresh(net, bridge),
                    icon: const Icon(Icons.refresh),
                    label: const Text('Refresh'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: FilledButton.tonalIcon(
                    onPressed: _connecting ? null : () => _disconnect(net, bridge),
                    icon: const Icon(Icons.link_off),
                    label: const Text('Disconnect'),
                  ),
                ),
              ],
            ),
            if (exitNodes.isNotEmpty) ...[
              const SizedBox(height: 24),
              Text('Exit Nodes', style: tt.labelLarge),
              const SizedBox(height: 8),
              DropdownButtonFormField<String>(
                initialValue: activeExitNode ?? '',
                decoration: const InputDecoration(
                  labelText: 'Preferred Tailscale exit node',
                  border: OutlineInputBorder(),
                ),
                items: [
                  const DropdownMenuItem<String>(
                    value: '',
                    child: Text('None'),
                  ),
                  ...exitNodes.map(
                    (entry) => DropdownMenuItem<String>(
                      value: entry['name'] as String? ?? '',
                      child: Text(entry['name'] as String? ?? 'Exit node'),
                    ),
                  ),
                ],
                onChanged: _connecting
                    ? null
                    : (value) => _setExitNode(net, bridge, value ?? ''),
              ),
              const SizedBox(height: 8),
              Text(
                'A Tailscale exit node can see clearnet destinations after traffic leaves the mesh. '
                'Websites see the exit node IP instead of yours.',
                style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
              ),
            ],
            if (peers.isNotEmpty) ...[
              const SizedBox(height: 24),
              Text('Peers', style: tt.labelLarge),
              const SizedBox(height: 8),
              ...peers.map(
                (peer) => ListTile(
                  contentPadding: EdgeInsets.zero,
                  leading: Icon(
                    peer['online'] == true ? Icons.circle : Icons.circle_outlined,
                    size: 14,
                    color: peer['online'] == true ? cs.primary : cs.outline,
                  ),
                  title: Text(peer['name'] as String? ?? 'Peer'),
                  subtitle: Text(peer['ip'] as String? ?? ''),
                  trailing: peer['isExitNode'] == true
                      ? const Icon(Icons.route_outlined)
                      : null,
                ),
              ),
            ],
          ] else ...[
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
                        'Sign in starts a browser-based login with '
                        '${_controllerType == _ControllerType.headscale ? "Headscale" : "Tailscale"}.',
                        style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
                      ),
                    ),
                  ],
                ),
              ),
            ],
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

          if (!isConfigured)
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

String _statusLabel(OverlayClientStatus status) => switch (status) {
  OverlayClientStatus.notConfigured => 'Not configured',
  OverlayClientStatus.connecting => 'Connecting',
  OverlayClientStatus.connected => 'Connected',
  OverlayClientStatus.disconnected => 'Disconnected',
  OverlayClientStatus.error => 'Error',
};

String _relayModeLabel(String raw) => switch (raw) {
  'mesh_preferred' => 'Mesh relay preferred',
  'derp' => 'Tailscale relay active',
  'direct' => 'Direct peer path',
  _ => raw,
};

class _StatusCard extends StatelessWidget {
  const _StatusCard({required this.title, required this.lines});

  final String title;
  final List<String> lines;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: cs.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: cs.outlineVariant),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title, style: tt.labelLarge),
          const SizedBox(height: 8),
          for (final line in lines.where((line) => line.trim().isNotEmpty))
            Padding(
              padding: const EdgeInsets.only(bottom: 4),
              child: Text(
                line,
                style: tt.bodyMedium?.copyWith(color: cs.onSurfaceVariant),
              ),
            ),
        ],
      ),
    );
  }
}
