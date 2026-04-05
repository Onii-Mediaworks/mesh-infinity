import 'dart:convert';
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';
import '../../../backend/models/network_models.dart';
import '../../../features/peers/peers_state.dart';
import '../../../platform/android_proximity_bridge.dart';
import '../../../platform/android_proximity_sync.dart';
import '../network_state.dart';
import '../widgets/transport_toggle_row.dart';
import '../widgets/network_stat_card.dart';
import 'tailscale_setup_screen.dart';
import 'vpn_screen.dart';
import 'zerotier_setup_screen.dart';

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
                  ListTile(
                    leading: const Icon(Icons.settings_ethernet_outlined),
                    title: const Text('Clearnet Port'),
                    subtitle: Text('TCP listen port: ${settings?.clearnetPort ?? 7234}'),
                    trailing: const Icon(Icons.chevron_right),
                    onTap: () => _showPortDialog(context, net, settings?.clearnetPort ?? 7234),
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
                  // Overlay transports — Mesh Infinity acts as the client
                  _OverlayTransportTile(
                    icon: Icons.vpn_key_outlined,
                    label: 'Tailscale',
                    description: 'Mesh Infinity is your Tailscale client',
                    status: net.tailscaleClientStatus,
                    onConfigure: () => Navigator.of(context).push(
                      MaterialPageRoute<void>(
                        builder: (_) => const TailscaleSetupScreen(),
                      ),
                    ),
                  ),
                  _OverlayTransportTile(
                    icon: Icons.lan_outlined,
                    label: 'ZeroTier',
                    description: 'Mesh Infinity is your ZeroTier client',
                    status: net.zerotierClientStatus,
                    onConfigure: () => Navigator.of(context).push(
                      MaterialPageRoute<void>(
                        builder: (_) => const ZeroTierSetupScreen(),
                      ),
                    ),
                  ),
                ],
              ),
            ),

            const Divider(height: 1),

            // VPN Settings
            ListTile(
              leading: const Icon(Icons.vpn_key_outlined),
              title: const Text('Traffic Routing'),
              subtitle: Text(_routingSummary(net)),
              trailing: const Icon(Icons.chevron_right),
              onTap: () => Navigator.of(context).push(
                MaterialPageRoute<void>(
                  builder: (_) => const VpnScreen(),
                ),
              ),
            ),

            const Divider(height: 1),

            // Trusted Contexts (§4.8.3)
            _Section(
              title: 'Trusted Contexts',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Padding(
                    padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
                    child: Text(
                      'Networks you control or that require authentication to join. '
                      'Peers discovered over trusted contexts can be found automatically. '
                      'Pairing over a trusted context gives the peer a trust boost.',
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ),
                  SwitchListTile(
                    secondary: const Icon(Icons.vpn_key_outlined),
                    title: const Text('Tailscale'),
                    subtitle: const Text('Pre-authenticated overlay network'),
                    value: net.tailscaleTrusted,
                    onChanged: (v) => net.setTrustedContext('tailscale', v),
                  ),
                  if (net.tailscaleTrusted)
                    const _OverlayRequirementsHint(
                      body: 'Tailscale peers are discoverable automatically and '
                          'receive a trust boost on pairing (+2 levels). '
                          'Configure the Tailscale client in Transports above.',
                    ),
                  SwitchListTile(
                    secondary: const Icon(Icons.lan_outlined),
                    title: const Text('ZeroTier'),
                    subtitle: const Text('Pre-authenticated overlay network'),
                    value: net.zerotierTrusted,
                    onChanged: (v) => net.setTrustedContext('zerotier', v),
                  ),
                  if (net.zerotierTrusted)
                    const _OverlayRequirementsHint(
                      body: 'ZeroTier peers are discoverable automatically and '
                          'receive a trust boost on pairing (+2 levels). '
                          'Configure the ZeroTier client in Transports above.',
                    ),
                  SwitchListTile(
                    secondary: const Icon(Icons.home_outlined),
                    title: const Text('Local Network (LAN)'),
                    subtitle: const Text('Enable for home/office networks you control'),
                    value: net.lanTrusted,
                    onChanged: (v) => net.setTrustedContext('lan', v),
                  ),
                  SwitchListTile(
                    secondary: const Icon(Icons.wifi_find_outlined),
                    title: const Text('Allow mDNS on trusted'),
                    subtitle: const Text('Automatic peer discovery on trusted networks'),
                    value: net.mdnsOnTrusted,
                    onChanged: (v) => net.setTrustedContext('mdns', v),
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
                      _DiscoveredPeerTile(peer: p),
                  ],
                ],
              ),
            ),

            const Divider(height: 1),

            const _AndroidProximitySection(),

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
                          NetworkStatCard(
                            label: 'Routing Entries',
                            value: '${net.stats!.routingEntries}',
                            icon: Icons.account_tree_outlined,
                          ),
                          NetworkStatCard(
                            label: 'WireGuard Sessions',
                            value: '${net.stats!.wireGuardSessions}',
                            icon: Icons.lock_outlined,
                          ),
                          NetworkStatCard(
                            label: 'Gossip Map',
                            value: '${net.stats!.gossipMapSize}',
                            icon: Icons.share_outlined,
                          ),
                          NetworkStatCard(
                            label: 'S&F Buffered',
                            value: '${net.stats!.sfPendingMessages}',
                            icon: Icons.inbox_outlined,
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

  void _showPortDialog(BuildContext context, NetworkState net, int current) {
    final ctrl = TextEditingController(text: '$current');
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Clearnet Port'),
        content: TextField(
          controller: ctrl,
          keyboardType: TextInputType.number,
          decoration: const InputDecoration(
            labelText: 'TCP port (1024–65535)',
            border: OutlineInputBorder(),
          ),
          autofocus: true,
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () {
              final port = int.tryParse(ctrl.text.trim());
              if (port != null && port >= 1024 && port <= 65535) {
                net.setClearnetPort(port);
                Navigator.pop(ctx);
              }
            },
            child: const Text('Save'),
          ),
        ],
      ),
    ).then((_) => ctrl.dispose());
  }

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }

  String _routingSummary(NetworkState net) {
    final status = switch (net.vpnConnectionStatus) {
      'connected' => 'Connected',
      'connecting' => 'Connecting',
      'blocked' => 'Blocked',
      'disconnecting' => 'Disconnecting',
      _ => 'Off',
    };

    return switch (net.vpnMode) {
      'mesh_only' => '$status · Mesh traffic stays in the mesh',
      'exit_node' => (net.selectedExitNodeId != null ||
              net.selectedTailscaleExitNode != null)
          ? '$status · Internet traffic uses a selected exit node'
          : '$status · Exit node mode without a selected node',
      'policy_based' => '$status · Custom rules choose where traffic goes',
      _ => 'Off · Use your normal connection unless you choose otherwise',
    };
  }
}

class _OverlayTransportTile extends StatelessWidget {
  const _OverlayTransportTile({
    required this.icon,
    required this.label,
    required this.description,
    required this.status,
    required this.onConfigure,
  });

  final IconData icon;
  final String label;
  final String description;
  final OverlayClientStatus status;
  final VoidCallback onConfigure;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    final (statusLabel, statusColor) = switch (status) {
      OverlayClientStatus.notConfigured => ('Not configured', cs.onSurfaceVariant),
      OverlayClientStatus.connecting    => ('Connecting…',    cs.primary),
      OverlayClientStatus.connected     => ('Connected',      Colors.green),
      OverlayClientStatus.disconnected  => ('Disconnected',   cs.onSurfaceVariant),
      OverlayClientStatus.error         => ('Error',          cs.error),
    };

    return ListTile(
      leading: Icon(icon, color: status == OverlayClientStatus.connected
          ? cs.primary : cs.onSurfaceVariant),
      title: Text(label),
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(description),
          const SizedBox(height: 2),
          Text(statusLabel,
              style: TextStyle(fontSize: 11, color: statusColor,
                  fontWeight: FontWeight.w600)),
        ],
      ),
      isThreeLine: true,
      trailing: TextButton(
        onPressed: onConfigure,
        child: Text(status == OverlayClientStatus.notConfigured
            ? 'Set up' : 'Manage'),
      ),
    );
  }
}

class _OverlayRequirementsHint extends StatelessWidget {
  const _OverlayRequirementsHint({required this.body});

  final String body;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
      child: Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: cs.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: cs.outlineVariant),
        ),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(Icons.info_outline, size: 16, color: cs.onSurfaceVariant),
            const SizedBox(width: 8),
            Expanded(
              child: Text(
                body,
                style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Discovered peer tile with optional Pair action
// ---------------------------------------------------------------------------

class _DiscoveredPeerTile extends StatefulWidget {
  const _DiscoveredPeerTile({required this.peer});

  final DiscoveredPeerModel peer;

  @override
  State<_DiscoveredPeerTile> createState() => _DiscoveredPeerTileState();
}

class _DiscoveredPeerTileState extends State<_DiscoveredPeerTile> {
  bool _pairing = false;

  Future<void> _pair() async {
    if (_pairing) return;
    setState(() => _pairing = true);

    final p = widget.peer;
    // Build a pairing payload matching what mi_pair_peer expects.
    final payload = jsonEncode({
      'ed25519_public': p.ed25519Pub,
      'x25519_public': p.x25519Pub,
      'display_name': p.displayName.isNotEmpty ? p.displayName : null,
      'transport_hints': [
        {'transport': 'clearnet', 'endpoint': p.address},
      ],
    });

    final bridge = context.read<BackendBridge>();
    final ok = bridge.pairPeer(payload);

    if (!mounted) return;
    setState(() => _pairing = false);

    if (ok) {
      // Refresh peers list so the new contact shows up.
      await context.read<PeersState>().loadPeers();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              'Paired with ${p.displayName.isNotEmpty ? p.displayName : p.id.substring(0, 16)}',
            ),
          ),
        );
      }
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Pairing failed')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final p = widget.peer;
    final label = p.displayName.isNotEmpty ? p.displayName
        : (p.id.length > 16 ? '${p.id.substring(0, 16)}…' : p.id);

    return ListTile(
      dense: true,
      leading: const Icon(Icons.device_hub_outlined, size: 20),
      title: Text(
        label,
        style: const TextStyle(fontSize: 13),
      ),
      subtitle: Text(
        p.address,
        style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
      ),
      trailing: p.canPair
          ? (_pairing
              ? const SizedBox(
                  width: 20, height: 20,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : TextButton(
                  onPressed: _pair,
                  child: const Text('Pair'),
                ))
          : null,
    );
  }
}

class _AndroidProximitySection extends StatefulWidget {
  const _AndroidProximitySection();

  @override
  State<_AndroidProximitySection> createState() =>
      _AndroidProximitySectionState();
}

class _AndroidProximitySectionState extends State<_AndroidProximitySection> {
  AndroidProximityCapabilities? _capabilities;
  List<AndroidWifiDirectPeer> _peers = const [];
  StreamSubscription<AndroidProximityEvent>? _sub;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
    _sub = AndroidProximityBridge.instance.events.listen((event) {
      if (event is WifiDirectStateChangedEvent ||
          event is WifiDirectPeersChangedEvent) {
        _load();
      }
    });
  }

  Future<void> _load() async {
    final bridge = context.read<BackendBridge>();
    final state = await AndroidProximitySync.syncCurrentState(bridge);
    if (!mounted) {
      return;
    }
    setState(() {
      _capabilities = _readCapabilities(state);
      _peers = _readPeers(state);
      _loading = false;
    });
  }

  Future<void> _toggleWifiDirectScan() async {
    final caps = _capabilities;
    if (caps == null) {
      return;
    }
    if (caps.wifiDirectDiscoveryActive) {
      await AndroidProximityBridge.instance.stopWifiDirectDiscovery();
      await _load();
      return;
    }

    final permissionGranted = caps.wifiDirectPermissionGranted ||
        await AndroidProximityBridge.instance.requestWifiDirectPermission();
    if (!permissionGranted) {
      if (!mounted) {
        return;
      }
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text(
            'Nearby Wi-Fi permission is required before WiFi Direct discovery can start.',
          ),
        ),
      );
      await _load();
      return;
    }

    await AndroidProximityBridge.instance.startWifiDirectDiscovery();
    await _load();
  }

  Future<void> _connectWifiPeer(AndroidWifiDirectPeer peer) async {
    if (_capabilities == null) {
      return;
    }
    final caps = _capabilities!;
    final permissionGranted = caps.wifiDirectPermissionGranted ||
        await AndroidProximityBridge.instance.requestWifiDirectPermission();
    if (!permissionGranted) {
      if (!mounted) {
        return;
      }
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text(
            'Nearby Wi-Fi permission is required before WiFi Direct can connect.',
          ),
        ),
      );
      await _load();
      return;
    }
    final ok = await AndroidProximityBridge.instance.connectWifiDirectPeer(
      peer.deviceAddress,
    );
    await _load();
    if (!mounted || ok) {
      return;
    }
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Could not start a WiFi Direct connection to that device.'),
      ),
    );
  }

  Future<void> _disconnectWifiPeer() async {
    await AndroidProximityBridge.instance.disconnectWifiDirectPeer();
    await _load();
  }

  @override
  void dispose() {
    _sub?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final caps = _capabilities;
    if (_loading) {
      return const SizedBox.shrink();
    }
    if (caps == null || (!caps.nfcAvailable && !caps.wifiDirectAvailable)) {
      return const SizedBox.shrink();
    }

    return _Section(
      title: 'Android Proximity',
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (caps.nfcAvailable)
            ListTile(
              leading: const Icon(Icons.nfc_outlined),
              title: const Text('NFC Tap-to-Pair'),
              subtitle: Text(
                caps.nfcEnabled
                    ? 'Ready to receive pairing payloads from nearby tags or devices'
                    : 'Supported, but NFC is turned off in system settings',
              ),
            ),
          if (caps.wifiDirectAvailable)
            ListTile(
              leading: const Icon(Icons.wifi_tethering_outlined),
              title: const Text('WiFi Direct Discovery'),
              subtitle: Text(_wifiSubtitle(caps, _peers.length)),
              trailing: Wrap(
                spacing: 8,
                children: [
                  if (caps.wifiDirectConnected)
                    OutlinedButton(
                      onPressed: _disconnectWifiPeer,
                      child: const Text('Disconnect'),
                    ),
                  FilledButton.tonal(
                    onPressed: caps.wifiDirectEnabled ? _toggleWifiDirectScan : null,
                    child: Text(caps.wifiDirectDiscoveryActive ? 'Stop' : 'Scan'),
                  ),
                ],
              ),
            ),
          if (caps.wifiDirectConnected)
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
              child: Text(
                _wifiConnectionSummary(caps),
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
              ),
            ),
          if (_peers.isNotEmpty)
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Nearby Android devices',
                    style: Theme.of(context).textTheme.titleSmall,
                  ),
                  const SizedBox(height: 8),
                  for (final peer in _peers)
                    ListTile(
                      contentPadding: EdgeInsets.zero,
                      leading: const Icon(Icons.devices_outlined),
                      title: Text(
                        peer.deviceName.isEmpty
                            ? 'Nearby device'
                            : peer.deviceName,
                      ),
                      subtitle: Text(_wifiPeerSubtitle(peer)),
                      trailing: (caps.wifiDirectConnected &&
                              caps.wifiDirectConnectedDeviceAddress ==
                                  peer.deviceAddress)
                          ? const Icon(Icons.check_circle_outline)
                          : OutlinedButton(
                              onPressed: peer.deviceAddress.isEmpty
                                  ? null
                                  : () => _connectWifiPeer(peer),
                              child: const Text('Connect'),
                            ),
                    ),
                ],
              ),
            ),
        ],
      ),
    );
  }

  String _wifiSubtitle(AndroidProximityCapabilities caps, int count) {
    if (!caps.wifiDirectEnabled) {
      return 'Supported, but WiFi Direct is currently unavailable';
    }
    if (!caps.wifiDirectPermissionGranted) {
      return 'Nearby Wi-Fi permission is required before this device can scan';
    }
    if (!caps.wifiDirectDiscoveryActive) {
      return 'Use WiFi Direct to find nearby Android devices without a router';
    }
    if (count == 0) {
      return 'Scanning for nearby Android devices';
    }
    return 'Found $count nearby ${count == 1 ? 'device' : 'devices'}';
  }

  String _wifiConnectionSummary(AndroidProximityCapabilities caps) {
    final role = switch (caps.wifiDirectConnectionRole) {
      'group_owner' => 'Connected as group owner',
      'client' => 'Connected as client',
      _ => 'Connected',
    };
    final groupOwner = caps.wifiDirectGroupOwnerAddress;
    if (groupOwner == null || groupOwner.isEmpty) {
      return role;
    }
    return '$role • group owner $groupOwner';
  }

  String _wifiPeerSubtitle(AndroidWifiDirectPeer peer) {
    final status = switch (peer.status) {
      'available' => 'Available',
      'connected' => 'Connected',
      'invited' => 'Invited',
      'failed' => 'Failed',
      'unavailable' => 'Unavailable',
      _ => 'Unknown',
    };
    return peer.deviceAddress.isEmpty
        ? status
        : '$status • ${peer.deviceAddress}';
  }

  AndroidProximityCapabilities? _readCapabilities(Map<String, dynamic> state) {
    if (state.isEmpty) {
      return null;
    }
    return AndroidProximityCapabilities.fromMap(
      Map<Object?, Object?>.from(state),
    );
  }

  List<AndroidWifiDirectPeer> _readPeers(Map<String, dynamic> state) {
    final raw = state['peers'];
    if (raw is! List) {
      return const [];
    }
    return raw
        .whereType<Map>()
        .map((peer) => AndroidWifiDirectPeer.fromMap(Map<Object?, Object?>.from(peer)))
        .toList(growable: false);
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
