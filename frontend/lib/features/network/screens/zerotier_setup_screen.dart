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
  /// Which controller backend the user has selected.
  _ControllerType _controllerType = _ControllerType.central;

  /// API key obtained from ZeroTier Central (my.zerotier.com) or the
  /// self-hosted controller admin panel.  Treated as a secret — obscured.
  final _apiKeyCtrl = TextEditingController();

  /// URL of a self-hosted ZeroTier controller, e.g. "https://zt.example.com".
  /// Only used when [_controllerType] is [_ControllerType.selfHosted].
  final _controllerUrlCtrl = TextEditingController();

  /// Text field for entering a ZeroTier network ID to join.
  final _networkIdCtrl = TextEditingController();

  /// True while a bridge call is in flight — disables buttons to prevent
  /// double-submission.
  bool _connecting = false;

  /// Human-readable error from the most recent failed bridge call.
  /// Null means no error is currently displayed.
  String? _errorMessage;

  /// Network IDs staged for joining during the initial-setup flow (before the
  /// user taps "Connect").  Shown as removable chips in the UI.  Distinct from
  /// the `networks` list that comes back from the backend after connection.
  final List<String> _pendingNetworks = [];

  @override
  void dispose() {
    _apiKeyCtrl.dispose();
    _controllerUrlCtrl.dispose();
    _networkIdCtrl.dispose();
    super.dispose();
  }

  /// Validates and stages a network ID for the pending-join list.
  ///
  /// ZeroTier network IDs are exactly 16 hexadecimal characters (e.g.
  /// "8056c2e21c000001").  The first 10 characters are the controller's
  /// node ID and the last 6 identify the network within that controller.
  /// Validation here prevents the user from submitting an obviously wrong
  /// value to the backend.
  void _addNetwork() {
    final id = _networkIdCtrl.text.trim();
    if (id.isEmpty) return;
    // ZeroTier network IDs are 16 hex characters.
    final validId = RegExp(r'^[0-9a-fA-F]{16}$').hasMatch(id);
    if (!validId) {
      setState(() => _errorMessage = 'Network ID must be 16 hex characters');
      return;
    }
    // Guard against duplicates in the pending list.
    if (_pendingNetworks.contains(id)) return;
    setState(() {
      _pendingNetworks.add(id);
      _networkIdCtrl.clear();
      _errorMessage = null;
    });
  }

  /// Submits the API key and network list to the Rust backend to start the
  /// ZeroTier client.
  ///
  /// The backend stores the credentials, connects to the controller, and joins
  /// each network ID in [_pendingNetworks].  Private networks require the
  /// network admin to authorise the new member before traffic flows.
  ///
  /// On failure the error from the bridge is surfaced in [_errorMessage] so
  /// the user can correct it (wrong API key, unreachable controller, etc.).
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

    // Empty string tells the backend to use ZeroTier Central (my.zerotier.com).
    final controllerUrl = _controllerType == _ControllerType.selfHosted
        ? _controllerUrlCtrl.text.trim()
        : '';

    try {
      // zerotierConnect passes the API key, optional controller URL, and the
      // list of 16-char network IDs to join.
      final ok = bridge.zerotierConnect(apiKey, controllerUrl, List.from(_pendingNetworks));
      if (!ok) {
        throw Exception(bridge.getLastError() ?? 'ZeroTier connection failed');
      }
      // Reload state so the status card reflects the new connection.
      await net.loadAll();
    } catch (e) {
      // Catch covers both bridge rejection (ok == false → Exception above) and
      // unexpected Dart errors.  Errors are shown inline rather than crashing.
      setState(() {
        _errorMessage = e.toString().replaceFirst('Exception: ', '');
      });
    } finally {
      // Always reset _connecting so the button re-enables after the call.
      if (mounted) setState(() => _connecting = false);
    }
  }

  /// Asks the Rust backend to re-sync ZeroTier state from the controller.
  ///
  /// Useful when a network admin has changed the topology, authorised new
  /// members, or when the device has regained connectivity after going offline.
  Future<void> _refresh(NetworkState net, BackendBridge bridge) async {
    setState(() => _connecting = true);
    final ok = bridge.zerotierRefresh();
    // Reload state regardless of whether the refresh succeeded so the UI
    // reflects the most recent information available from the backend.
    await net.loadAll();
    if (!ok && mounted) {
      setState(() {
        _errorMessage = bridge.getLastError() ?? 'Could not refresh ZeroTier';
      });
    }
    if (mounted) {
      setState(() => _connecting = false);
    }
  }

  /// Disconnects the ZeroTier client and clears stored credentials from Rust.
  ///
  /// After disconnection the status card returns to "Not configured" and
  /// the setup form is shown again so the user can re-enroll if desired.
  Future<void> _disconnect(NetworkState net, BackendBridge bridge) async {
    setState(() => _connecting = true);
    final ok = bridge.zerotierDisconnect();
    await net.loadAll();
    if (!ok && mounted) {
      setState(() {
        _errorMessage = bridge.getLastError() ?? 'Could not disconnect ZeroTier';
      });
    }
    if (mounted) {
      setState(() => _connecting = false);
    }
  }

  /// Joins an additional ZeroTier network while already connected.
  ///
  /// Used after initial setup when the user wants to add more networks
  /// without going through the full enrolment form again.  Validates the
  /// 16-char network ID before passing it to the bridge.
  Future<void> _joinNetwork(NetworkState net, BackendBridge bridge) async {
    final id = _networkIdCtrl.text.trim();
    if (!RegExp(r'^[0-9a-fA-F]{16}$').hasMatch(id)) {
      setState(() => _errorMessage = 'Network ID must be 16 hex characters');
      return;
    }
    final ok = bridge.zerotierJoinNetwork(id);
    await net.loadAll();
    if (!ok && mounted) {
      setState(() {
        _errorMessage = bridge.getLastError() ?? 'Could not join that network';
      });
    } else if (mounted) {
      // Clear the field on success so the user can enter the next network ID.
      setState(() {
        _networkIdCtrl.clear();
      });
    }
  }

  /// Toggles whether to prefer Mesh Infinity relay infrastructure over
  /// ZeroTier's own relay servers (PLANET/MOON nodes).
  ///
  /// When enabled, the backend routes traffic through mesh relays instead of
  /// reaching out to ZeroTier's centralised infrastructure — a privacy
  /// improvement for users running a self-hosted controller.
  Future<void> _setPreferMeshRelay(
    NetworkState net,
    BackendBridge bridge,
    bool enabled,
  ) async {
    final ok = bridge.zerotierSetPreferMeshRelay(enabled);
    await net.loadAll();
    if (!ok && mounted) {
      setState(() {
        _errorMessage =
            bridge.getLastError() ?? 'Could not update relay preference';
      });
    }
  }

  /// Authorises or deauthorises a ZeroTier network member.
  ///
  /// This is only available when Mesh Infinity manages a ZeroTier network as
  /// the controller (i.e. this device's ZeroTier node is the network owner).
  /// [networkId] identifies the network; [nodeId] identifies the member node.
  Future<void> _setMemberAuthorized(
    NetworkState net,
    BackendBridge bridge,
    String networkId,
    String nodeId,
    bool authorized,
  ) async {
    final ok = bridge.zerotierSetMemberAuthorized(networkId, nodeId, authorized);
    await net.loadAll();
    if (!ok && mounted) {
      setState(() {
        _errorMessage = bridge.getLastError() ?? 'Could not update member';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;
    final net = context.watch<NetworkState>();
    final bridge = context.read<BackendBridge>();
    final overlay = net.zerotierOverlay;
    final nodeId = overlay['nodeId'] as String?;
    final controller = overlay['controller'] as String?;
    final preferMeshRelay = overlay['preferMeshRelay'] == true;
    final relayMode = overlay['relayMode'] as String?;
    final networks = (overlay['networks'] as List?)
            ?.whereType<Map>()
            .map((entry) => Map<String, dynamic>.from(entry))
            .toList() ??
        const <Map<String, dynamic>>[];
    final members = (overlay['members'] as List?)
            ?.whereType<Map>()
            .map((entry) => Map<String, dynamic>.from(entry))
            .toList() ??
        const <Map<String, dynamic>>[];
    final isConfigured =
        net.zerotierClientStatus != OverlayClientStatus.notConfigured;

    return Scaffold(
      appBar: AppBar(title: const Text('ZeroTier')),
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
              'Mesh Infinity acts as your ZeroTier client for an existing '
              'zeronet — no separate app needed. On mobile, it shares the VPN '
              'slot with mesh routing.',
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            ),
          ),
          const SizedBox(height: 24),
          _StatusCard(
            title: 'Status',
            lines: [
              _statusLabel(net.zerotierClientStatus),
              if (nodeId != null && nodeId.isNotEmpty) 'Node ID: $nodeId',
              if (controller != null && controller.isNotEmpty) controller,
              if (relayMode != null && relayMode.isNotEmpty)
                'Relay: ${_relayModeLabel(relayMode)}',
            ],
          ),

          if (isConfigured) ...[
            const SizedBox(height: 16),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text('Prefer mesh relay over ZeroTier relay'),
              subtitle: const Text(
                'Avoid ZeroTier relay infrastructure when a mesh relay path is available.',
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
            const SizedBox(height: 24),
            Text('Join Another Network', style: tt.labelLarge),
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
                    onSubmitted: (_) => _joinNetwork(net, bridge),
                  ),
                ),
                const SizedBox(width: 8),
                FilledButton.tonal(
                  onPressed: _connecting ? null : () => _joinNetwork(net, bridge),
                  child: const Text('Join'),
                ),
              ],
            ),
            if (networks.isNotEmpty) ...[
              const SizedBox(height: 16),
              Text('Networks', style: tt.labelLarge),
              const SizedBox(height: 8),
              ...networks.map(
                (network) => ListTile(
                  contentPadding: EdgeInsets.zero,
                  leading: Icon(
                    _networkAuthorized(network) ? Icons.check_circle : Icons.pending,
                    color: _networkAuthorized(network) ? cs.primary : cs.tertiary,
                  ),
                  title: Text(network['name'] as String? ?? network['networkId'] as String? ?? 'Network'),
                  subtitle: Text(
                    [
                      network['networkId'] as String? ?? '',
                      network['assignedIp'] as String? ?? '',
                      _networkStatusLabel(network['authStatus'] as String?),
                    ].where((value) => value.isNotEmpty).join(' · '),
                  ),
                  trailing: Text('${network['memberCount'] ?? 0}'),
                ),
              ),
            ],
            if (members.isNotEmpty) ...[
              const SizedBox(height: 16),
              Text('Members', style: tt.labelLarge),
              const SizedBox(height: 8),
              ...members.map((member) {
                final authorized = member['authorized'] == true;
                final networkId = member['networkId'] as String? ?? '';
                return ListTile(
                  contentPadding: EdgeInsets.zero,
                  title: Text(member['name'] as String? ?? member['nodeId'] as String? ?? 'Member'),
                  subtitle: Text(
                    [
                      networkId,
                      member['nodeId'] as String? ?? '',
                      ((member['ips'] as List?)?.cast<String>() ?? const <String>[]).join(', '),
                    ].where((value) => value.isNotEmpty).join(' · '),
                  ),
                  trailing: networkId.isEmpty
                      ? null
                      : TextButton(
                          onPressed: _connecting
                              ? null
                              : () => _setMemberAuthorized(
                                    net,
                                    bridge,
                                    networkId,
                                    member['nodeId'] as String? ?? '',
                                    !authorized,
                                  ),
                          child: Text(authorized ? 'Deauthorize' : 'Authorize'),
                        ),
                );
              }),
            ],
          ] else ...[
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
                  title: Text(id, style: const TextStyle(fontFamily: 'monospace')),
                  trailing: IconButton(
                    icon: const Icon(Icons.close, size: 18),
                    onPressed: () => setState(() => _pendingNetworks.remove(id)),
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

          if (!isConfigured)
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

String _statusLabel(OverlayClientStatus status) => switch (status) {
  OverlayClientStatus.notConfigured => 'Not configured',
  OverlayClientStatus.connecting => 'Connecting',
  OverlayClientStatus.connected => 'Connected',
  OverlayClientStatus.disconnected => 'Disconnected',
  OverlayClientStatus.error => 'Error',
};

bool _networkAuthorized(Map<String, dynamic> network) =>
    (network['authStatus'] as String?) == 'authorized';

String _networkStatusLabel(String? raw) => switch (raw) {
  'authorized' => 'Authorized',
  'awaitingauthorization' => 'Awaiting approval',
  'awaiting_authorization' => 'Awaiting approval',
  'unauthorized' => 'Unauthorized',
  _ => 'Unknown',
};

String _relayModeLabel(String raw) => switch (raw) {
  'mesh_preferred' => 'Mesh relay preferred',
  'vendor_relay' => 'ZeroTier relay active',
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
