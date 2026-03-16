import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../network_state.dart';
import '../widgets/transport_toggle_row.dart';
import '../widgets/network_stat_card.dart';

class NetworkScreen extends StatelessWidget {
  const NetworkScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final net = context.watch<NetworkState>();
    final settings = net.settings;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Network'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh',
            onPressed: net.loadAll,
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: net.loadAll,
        child: ListView(
          children: [
            // Node mode
            _Section(
              title: 'Node Mode',
              child: Padding(
                padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
                child: SegmentedButton<int>(
                  segments: const [
                    ButtonSegment(value: 0, label: Text('Client')),
                    ButtonSegment(value: 1, label: Text('Server')),
                    ButtonSegment(value: 2, label: Text('Dual')),
                  ],
                  selected: {settings?.nodeMode ?? 0},
                  onSelectionChanged: (s) => net.setNodeMode(s.first),
                ),
              ),
            ),

            const Divider(height: 1),

            // Transports
            _Section(
              title: 'Transports',
              child: Column(
                children: [
                  TransportToggleRow(
                    icon: Icons.security_outlined,
                    label: 'Tor',
                    description: 'Anonymise traffic via the Tor network',
                    value: settings?.enableTor ?? false,
                    onChanged: (v) => net.toggleTransport('tor', v),
                  ),
                  TransportToggleRow(
                    icon: Icons.public_outlined,
                    label: 'Clearnet',
                    description: 'WireGuard over direct internet (lowest priority)',
                    value: settings?.enableClearnet ?? false,
                    onChanged: (v) => net.toggleTransport('clearnet', v),
                  ),
                  TransportToggleRow(
                    icon: Icons.public_off_outlined,
                    label: 'Clearnet Fallback',
                    description:
                        'Allow this node to originate clearnet hops when all '
                        'privacy transports fail. Disable to prevent this node '
                        'from being the clearnet origin; relay hops are unaffected.',
                    value: settings?.clearnetFallback ?? true,
                    onChanged: (v) => net.toggleTransport('clearnet_fallback', v),
                  ),
                  TransportToggleRow(
                    icon: Icons.vpn_lock_outlined,
                    label: 'I2P',
                    description: 'Route through the I2P overlay network',
                    value: settings?.enableI2p ?? false,
                    onChanged: (v) => net.toggleTransport('i2p', v),
                  ),
                  TransportToggleRow(
                    icon: Icons.bluetooth_outlined,
                    label: 'Bluetooth',
                    description: 'Local peer-to-peer via Bluetooth',
                    value: settings?.enableBluetooth ?? false,
                    onChanged: (v) => net.toggleTransport('bluetooth', v),
                  ),
                  TransportToggleRow(
                    icon: Icons.radio_outlined,
                    label: 'RF Radio',
                    description: 'LoRa/SDR radio frequency transport',
                    value: settings?.enableRf ?? false,
                    onChanged: (v) => net.toggleTransport('rf', v),
                  ),
                  TransportToggleRow(
                    icon: Icons.share_outlined,
                    label: 'Mesh Discovery',
                    description: 'Discover peers via the mesh network',
                    value: settings?.meshDiscovery ?? false,
                    onChanged: (v) => net.toggleTransport('mesh_discovery', v),
                  ),
                  TransportToggleRow(
                    icon: Icons.route_outlined,
                    label: 'Allow Relays',
                    description: 'Route through relay nodes when needed',
                    value: settings?.allowRelays ?? false,
                    onChanged: (v) => net.toggleTransport('relays', v),
                  ),
                ],
              ),
            ),

            const Divider(height: 1),

            // mDNS Discovery
            _Section(
              title: 'Local Discovery (mDNS)',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  SwitchListTile(
                    secondary: const Icon(Icons.wifi_find_outlined),
                    title: const Text('mDNS'),
                    subtitle: const Text('Discover peers on the local network'),
                    value: net.mdnsRunning,
                    onChanged: (v) =>
                        v ? net.enableMdns() : net.disableMdns(),
                  ),
                  if (net.discoveredPeers.isNotEmpty) ...[
                    const Padding(
                      padding: EdgeInsets.fromLTRB(16, 8, 16, 4),
                      child: Text('Discovered peers'),
                    ),
                    for (final p in net.discoveredPeers)
                      ListTile(
                        dense: true,
                        leading: const Icon(Icons.device_hub_outlined, size: 20),
                        title: Text(
                          p.id.length > 16 ? p.id.substring(0, 16) : p.id,
                          style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                        ),
                        subtitle: Text(p.address),
                      ),
                  ],
                ],
              ),
            ),

            const Divider(height: 1),

            // Network stats
            _Section(
              title: 'Statistics',
              child: Padding(
                padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
                child: net.stats == null
                    ? const Text('No stats available')
                    : GridView.count(
                        crossAxisCount: 2,
                        shrinkWrap: true,
                        physics: const NeverScrollableScrollPhysics(),
                        crossAxisSpacing: 8,
                        mainAxisSpacing: 8,
                        childAspectRatio: 1.6,
                        children: [
                          NetworkStatCard(
                            label: 'Active Connections',
                            value: '${net.stats!.activeConnections}',
                            icon: Icons.hub_outlined,
                          ),
                          NetworkStatCard(
                            label: 'Bytes Sent',
                            value: _formatBytes(net.stats!.bytesSent),
                            icon: Icons.upload_outlined,
                          ),
                          NetworkStatCard(
                            label: 'Bytes Received',
                            value: _formatBytes(net.stats!.bytesReceived),
                            icon: Icons.download_outlined,
                          ),
                          NetworkStatCard(
                            label: 'Routes Delivered',
                            value: '${net.stats!.deliveredRoutes}',
                            icon: Icons.route_outlined,
                          ),
                        ],
                      ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }
}

class _Section extends StatelessWidget {
  const _Section({required this.title, required this.child});

  final String title;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 20, 16, 8),
          child: Text(
            title,
            style: Theme.of(context).textTheme.labelMedium?.copyWith(
              color: Theme.of(context).colorScheme.primary,
              fontWeight: FontWeight.bold,
            ),
          ),
        ),
        child,
      ],
    );
  }
}
