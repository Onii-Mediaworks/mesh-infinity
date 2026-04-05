import 'package:flutter/foundation.dart' show defaultTargetPlatform, kDebugMode;
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';
import '../../../platform/android_keystore_bridge.dart';
import '../../../platform/android_proximity_bridge.dart';
import '../../../platform/android_proximity_sync.dart';

class DebugScreen extends StatelessWidget {
  const DebugScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final bridge = context.read<BackendBridge>();
    final theme = Theme.of(context);
    final cs = theme.colorScheme;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Developer Options'),
        backgroundColor: kDebugMode ? cs.errorContainer : null,
        foregroundColor: kDebugMode ? cs.onErrorContainer : null,
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: cs.errorContainer.withValues(alpha: 0.4),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Row(
              children: [
                Icon(Icons.bug_report_outlined, color: cs.error, size: 18),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    'Debug build only. This screen is removed from production builds.',
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: cs.onErrorContainer,
                    ),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
          const _SectionHeader('Inspect'),
          ListTile(
            leading: const Icon(Icons.manage_search_outlined),
            title: const Text('Internal state'),
            subtitle: const Text(
              'Identity, routing, settings, and network stats',
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => Navigator.push(
              context,
              MaterialPageRoute(
                builder: (_) => _StateInspectorScreen(bridge: bridge),
              ),
            ),
          ),
          if (defaultTargetPlatform == TargetPlatform.android)
            _AndroidPlatformDiagnostics(bridge: bridge),
          const Divider(height: 1),
          const _SectionHeader('Runtime'),
          const _KV('Build mode', kDebugMode ? 'debug' : 'release'),
          _KV('Platform', defaultTargetPlatform.name),
          _KV('Backend available', bridge.isAvailable ? 'yes' : 'no'),
          _KV(
            'Context address',
            '0x${bridge.contextAddress.toRadixString(16)}',
          ),
          _KV('Last backend error', bridge.getLastError() ?? '(none)'),
          const SizedBox(height: 24),
        ],
      ),
    );
  }
}

class _AndroidPlatformDiagnostics extends StatelessWidget {
  const _AndroidPlatformDiagnostics({required this.bridge});

  final BackendBridge bridge;

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<_AndroidPlatformSnapshot>(
      future: _loadSnapshot(),
      builder: (context, snapshot) {
        final data = snapshot.data;
        if (data == null) {
          return const ListTile(
            leading: Icon(Icons.developer_board_outlined),
            title: Text('Android platform adapters'),
            subtitle: Text('Loading keystore and proximity state'),
          );
        }
        return Column(
          children: [
            ListTile(
              leading: const Icon(Icons.lock_outline),
              title: const Text('Android keystore'),
              subtitle: Text(
                data.keystoreAvailable
                    ? 'Available to the running app'
                    : 'Unavailable on this device or build',
              ),
            ),
            ListTile(
              leading: const Icon(Icons.wifi_tethering_outlined),
              title: const Text('Android proximity'),
              subtitle: Text(
                _buildProximitySummary(data.proximityCapabilities),
              ),
            ),
          ],
        );
      },
    );
  }

  Future<_AndroidPlatformSnapshot> _loadSnapshot() async {
    final keystoreAvailable = await AndroidKeystoreBridge.instance.isAvailable();
    final state = await AndroidProximitySync.syncCurrentState(bridge);
    final proximityCapabilities = state.isEmpty
        ? null
        : AndroidProximityCapabilities.fromMap(Map<Object?, Object?>.from(state));
    return _AndroidPlatformSnapshot(
      keystoreAvailable: keystoreAvailable,
      proximityCapabilities: proximityCapabilities,
    );
  }

  String _buildProximitySummary(AndroidProximityCapabilities? caps) {
    if (caps == null) {
      return 'Not supported on this platform';
    }
    final nfc = caps.nfcAvailable
        ? (caps.nfcEnabled ? 'NFC ready' : 'NFC off')
        : 'No NFC';
    final wifiDirect = caps.wifiDirectAvailable
        ? (caps.wifiDirectEnabled ? 'WiFi Direct ready' : 'WiFi Direct off')
        : 'No WiFi Direct';
    return '$nfc, $wifiDirect';
  }
}

class _AndroidPlatformSnapshot {
  const _AndroidPlatformSnapshot({
    required this.keystoreAvailable,
    required this.proximityCapabilities,
  });

  final bool keystoreAvailable;
  final AndroidProximityCapabilities? proximityCapabilities;
}

class _KV extends StatelessWidget {
  const _KV(this.label, this.value);

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final tt = Theme.of(context).textTheme;
    final cs = Theme.of(context).colorScheme;

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(child: Text(label, style: tt.bodyMedium)),
          const SizedBox(width: 16),
          Flexible(
            child: Text(
              value,
              textAlign: TextAlign.right,
              style: tt.bodyMedium?.copyWith(
                color: cs.onSurfaceVariant,
                fontFamily: 'monospace',
              ),
            ),
          ),
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
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 6),
      child: Text(
        title,
        style: Theme.of(context).textTheme.labelMedium?.copyWith(
          color: Theme.of(context).colorScheme.primary,
          fontWeight: FontWeight.w600,
        ),
      ),
    );
  }
}

class _StateInspectorScreen extends StatelessWidget {
  const _StateInspectorScreen({required this.bridge});

  final BackendBridge bridge;

  @override
  Widget build(BuildContext context) {
    final identity = bridge.fetchLocalIdentity();
    final settings = bridge.fetchSettings();
    final stats = bridge.getNetworkStats();
    final diagnostics = bridge.getDiagnosticReport();
    final routing_diagnostics = diagnostics?['routing_stats'];
    final identity_diagnostics = diagnostics?['identity_status'];
    final memory_diagnostics = diagnostics?['memory_usage'];
    final transport_diagnostics = diagnostics?['transport_status'];

    return Scaffold(
      appBar: AppBar(title: const Text('State Inspector')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _InspectorSection(
            'Identity',
            entries: [
              _InspectorEntry(
                'Peer ID',
                identity?.peerId.isEmpty ?? true ? '(none)' : identity!.peerId,
              ),
              _InspectorEntry('Name', identity?.name ?? '(none)'),
              _InspectorEntry('Public key', identity?.publicKey ?? '(none)'),
            ],
          ),
          _InspectorSection(
            'Settings',
            entries: [
              _InspectorEntry('Node mode', '${settings?.nodeMode ?? 0}'),
              _InspectorEntry('Threat context', '${bridge.getThreatContext()}'),
              _InspectorEntry('Active tier', '${settings?.activeTier ?? 0}'),
              _InspectorEntry(
                'Bandwidth profile',
                '${settings?.bandwidthProfile ?? 1}',
              ),
              _InspectorEntry('Tor', '${settings?.enableTor ?? false}'),
              _InspectorEntry(
                'Clearnet',
                '${settings?.enableClearnet ?? false}',
              ),
              _InspectorEntry('I2P', '${settings?.enableI2p ?? false}'),
              _InspectorEntry(
                'Bluetooth',
                '${settings?.enableBluetooth ?? false}',
              ),
              _InspectorEntry(
                'Mesh discovery',
                '${settings?.meshDiscovery ?? false}',
              ),
            ],
          ),
          _InspectorSection(
            'Network stats',
            entries: [
              _InspectorEntry(
                'Connected peers',
                '${stats?['connectedPeers'] ?? 0}',
              ),
              _InspectorEntry(
                'Active tunnels',
                '${stats?['activeTunnels'] ?? 0}',
              ),
              _InspectorEntry(
                'Routing entries',
                '${stats?['routingEntries'] ?? 0}',
              ),
              _InspectorEntry(
                'Gossip map size',
                '${stats?['gossipMapSize'] ?? 0}',
              ),
            ],
          ),
          _InspectorSection(
            'Diagnostic report',
            entries: [
              _InspectorEntry(
                'Timestamp',
                '${diagnostics?['timestamp'] ?? 0}',
              ),
              _InspectorEntry(
                'Transport entries',
                transport_diagnostics is List
                    ? '${transport_diagnostics.length}'
                    : '0',
              ),
              _InspectorEntry(
                'Total routes',
                routing_diagnostics is Map
                    ? '${routing_diagnostics['total_routes'] ?? 0}'
                    : '0',
              ),
              _InspectorEntry(
                'Direct peers',
                routing_diagnostics is Map
                    ? '${routing_diagnostics['direct_peers'] ?? 0}'
                    : '0',
              ),
              _InspectorEntry(
                'Vault unlocked',
                identity_diagnostics is Map
                    ? '${identity_diagnostics['vault_unlocked'] ?? false}'
                    : 'false',
              ),
              _InspectorEntry(
                'Onboarding complete',
                identity_diagnostics is Map
                    ? '${identity_diagnostics['onboarding_complete'] ?? false}'
                    : 'false',
              ),
              _InspectorEntry(
                'RSS bytes',
                memory_diagnostics is Map
                    ? '${memory_diagnostics['rss_bytes'] ?? 0}'
                    : '0',
              ),
            ],
          ),
          const SizedBox(height: 24),
        ],
      ),
    );
  }
}

class _InspectorSection extends StatelessWidget {
  const _InspectorSection(this.title, {required this.entries});

  final String title;
  final List<_InspectorEntry> entries;

  @override
  Widget build(BuildContext context) {
    final tt = Theme.of(context).textTheme;
    final cs = Theme.of(context).colorScheme;

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      clipBehavior: Clip.antiAlias,
      child: ExpansionTile(
        title: Text(title, style: tt.titleSmall),
        children: entries
            .map(
              (e) => Padding(
                padding: const EdgeInsets.fromLTRB(16, 4, 16, 4),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Expanded(child: Text(e.key, style: tt.bodySmall)),
                    const SizedBox(width: 16),
                    Flexible(
                      child: Text(
                        e.value,
                        textAlign: TextAlign.right,
                        style: tt.bodySmall?.copyWith(
                          fontFamily: 'monospace',
                          color: cs.onSurfaceVariant,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            )
            .toList(),
      ),
    );
  }
}

class _InspectorEntry {
  const _InspectorEntry(this.key, this.value);

  final String key;
  final String value;
}
